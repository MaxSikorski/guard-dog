//! The fact model (`crates/gd-core/src/fact.rs`, `view.rs`): hostile text stays
//! untrusted, checked strings refuse bad input, every fact family Judge B reads
//! and every kind the lab manifest records has a claim, and setup-level facts
//! are derived the same way whatever order the facts arrive in.
//!
//! The JSON here is only for comparing and for the untrusted-shape check; the
//! tests are the one place besides `gd-store` that calls `serde_json::to_*` on
//! facts.

// Test-only crate: failed checks are panics. See expected_matches.rs.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use gd_core::*;
use proptest::prelude::*;
use serde_json::Value as Json;
use toml::{Table, Value};

// ---------------------------------------------------------------- helpers

/// Fixed seed, like every property test here; `GD_PROPTEST_SEED` explores another.
fn config() -> ProptestConfig {
    let seed = std::env::var("GD_PROPTEST_SEED")
        .ok()
        .and_then(|v| v.trim().parse::<u64>().ok())
        .unwrap_or(0x6764_5f70_726f_7074);
    ProptestConfig {
        rng_seed: proptest::test_runner::RngSeed::Fixed(seed),
        ..ProptestConfig::default()
    }
}

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(rel: &str) -> String {
    fs::read_to_string(root().join(rel)).unwrap_or_else(|e| panic!("{rel}: {e}"))
}

fn cat(id: &str) -> CatalogId {
    CatalogId::parse(id).unwrap()
}

fn instance(id: &str) -> InstanceRef {
    InstanceRef {
        catalog: cat(id),
        instance: InstanceName::parse("").unwrap(),
    }
}

fn version(v: &str) -> PlainVersion {
    PlainVersion::parse(v).unwrap()
}

fn source(sensor: SensorId) -> Source {
    Source {
        sensor,
        backend: Backend::Fake,
    }
}

fn fact(subject: Subject, claim: Claim) -> Fact {
    Fact::new(
        subject,
        claim,
        source(SensorId::Fixture),
        Timestamp(1_700_000_000),
        vec![],
    )
    .unwrap()
}

fn container(name: &str) -> RunsAs {
    RunsAs::Container {
        name: OutsideText::new(name),
        image: OutsideText::new("img"),
        digest: None,
    }
}

fn service_fact(id: &str, v: &str, method: Method) -> Fact {
    fact(
        Subject::Service(instance(id)),
        Claim::Service {
            state: Observed::Seen(ServiceState::Running),
            version: Observed::Seen(version(v)),
            runs_as: container(id),
            method,
        },
    )
}

/// The view as text, for equality. Tuples in a list, because JSON object keys
/// must be strings and the maps are keyed by structs.
fn render(view: &SetupView) -> String {
    serde_json::to_string(&(
        &view.chain,
        &view.platform,
        &view.word_size,
        &view.block_storage,
        &view.exposure,
        view.services().collect::<Vec<_>>(),
        view.states().collect::<Vec<_>>(),
        view.settings().collect::<Vec<_>>(),
        format!("{:?}", view.blind_spots),
        view.packages().collect::<Vec<_>>(),
    ))
    .unwrap()
}

fn json<T: serde::Serialize>(value: &T) -> String {
    serde_json::to_string(value).unwrap()
}

fn unknown<T>(reason: UnknownReason) -> Observed<T> {
    Observed::Unknown(Unknown::new(reason))
}

// -------------------------------------------- hostile text and Untrusted

fn hostile_text() -> impl Strategy<Value = String> {
    const DANGEROUS: &str = "\u{0}\u{7}\t\n\r\u{1b}\u{7f}\u{85}\u{9b}\\&<>\"'\u{ad}\u{61c}\
        \u{200b}\u{200d}\u{200f}\u{2028}\u{202e}\u{2066}\u{2069}\u{2800}\u{feff}\u{fe0f}\
        \u{e0041}\u{e007f}\u{e0100}\u{338}\u{301}\u{1d173}{}[]:,";
    let dangerous = proptest::sample::select(DANGEROUS.chars().collect::<Vec<_>>());
    proptest::collection::vec(prop_oneof![any::<char>(), dangerous], 0..64)
        .prop_map(|chars| chars.into_iter().collect())
}

/// A fact with `text` in every slot that takes outside text.
fn hostile_fact(text: &str) -> Fact {
    let u = |tag: &str| OutsideText::new(&format!("ZQX{tag}{text}"));
    Fact::new(
        Subject::Service(instance("bitcoin-core")),
        Claim::Host {
            os: u("os"),
            os_version: Observed::Seen(version("12.1")),
            kernel: Observed::Unknown(Unknown::with_detail(
                UnknownReason::Unparsable,
                &format!("ZQXdetail{text}"),
            )),
            arch: Observed::Seen(Arch::Other(u("arch"))),
        },
        source(SensorId::Nip11),
        Timestamp(5),
        vec![
            Evidence::new(
                CallId::parse("getnetworkinfo").unwrap(),
                &format!("ZQXevidence{text}"),
            ),
            Evidence::new(CallId::parse("version").unwrap(), text),
        ],
    )
    .unwrap()
}

fn hostile_other_claims(text: &str) -> Vec<Claim> {
    let u = |tag: &str| OutsideText::new(&format!("ZQX{tag}{text}"));
    vec![
        Claim::Unrecognized {
            candidates: vec![],
            runs_as: RunsAs::Container {
                name: u("name"),
                image: u("image"),
                digest: None,
            },
            version_label: Some(u("vlabel")),
            source_label: Some(u("slabel")),
        },
        Claim::Unrecognized {
            candidates: vec![],
            runs_as: RunsAs::Unit { name: u("unit") },
            version_label: None,
            source_label: None,
        },
        Claim::Unrecognized {
            candidates: vec![],
            runs_as: RunsAs::Binary {
                path: u("path"),
                sha256: None,
            },
            version_label: None,
            source_label: None,
        },
        Claim::BlockStorage(Observed::Seen(FsKind::Other(u("fs")))),
    ]
}

/// Every string in `value` that contains the marker must sit directly under an
/// `"untrusted"` key.
fn markers_only_under_untrusted(value: &Json, key: Option<&str>) {
    match value {
        Json::String(s) => {
            if s.contains("ZQX") {
                assert_eq!(
                    key,
                    Some("untrusted"),
                    "outside text outside its wrapper: {s:?}"
                );
            }
        }
        Json::Array(items) => items
            .iter()
            .for_each(|v| markers_only_under_untrusted(v, key)),
        Json::Object(map) => map
            .iter()
            .for_each(|(k, v)| markers_only_under_untrusted(v, Some(k))),
        _ => {}
    }
}

proptest! {
    #![proptest_config(config())]

    #[test]
    fn hostile_strings_never_escape_untrusted(text in hostile_text()) {
        let mut facts = vec![hostile_fact(&text)];
        facts.extend(
            hostile_other_claims(&text)
                .into_iter()
                .map(|claim| fact(Subject::Host, claim)),
        );
        for f in &facts {
            // Debug is for logs: it must hold no outside text and no control character.
            let debug = format!("{f:?}");
            prop_assert!(!debug.contains("ZQX"), "{debug}");
            prop_assert!(!debug.chars().any(char::is_control), "{debug:?}");

            // JSON keeps outside text under its wrapper and round-trips byte for byte.
            let text_json = json(f);
            let parsed: Json = serde_json::from_str(&text_json).unwrap();
            markers_only_under_untrusted(&parsed, None);
            let back: Fact = serde_json::from_str(&text_json).unwrap();
            prop_assert_eq!(json(&back), text_json);

            // Evidence stays small, and the terminal form of it is safe.
            prop_assert!(f.evidence().len() <= MAX_EVIDENCE);
            for e in f.evidence() {
                prop_assert!(e.raw().byte_len() <= MAX_EVIDENCE_BYTES);
                let shown = e.raw().escape_for_terminal();
                prop_assert!(!shown.chars().any(char::is_control), "{shown:?}");
            }
        }
    }
}

// ------------------------------------------------- checked constructors

fn reference_slug(t: &str, underscore: bool, empty_ok: bool) -> bool {
    let cs: Vec<char> = t.chars().collect();
    if cs.is_empty() {
        return empty_ok;
    }
    cs.len() <= 40
        && (cs[0].is_ascii_lowercase() || cs[0].is_ascii_digit())
        && cs
            .iter()
            .all(|&c| matches!(c, 'a'..='z' | '0'..='9' | '-') || (underscore && c == '_'))
}

fn reference_version(t: &str) -> bool {
    let ok = |s: &str| {
        s.starts_with(|c: char| c.is_ascii_alphanumeric())
            && s.chars().all(
                |c| matches!(c, '0'..='9' | 'a'..='z' | 'A'..='Z' | '.' | '+' | '~' | '_' | '-'),
            )
    };
    if !(1..=64).contains(&t.chars().count()) {
        return false;
    }
    match t.split_once('!') {
        Some((e, rest)) => !e.is_empty() && e.chars().all(|c| c.is_ascii_digit()) && ok(rest),
        None => ok(t),
    }
}

fn mostly_valid() -> impl Strategy<Value = String> {
    prop_oneof![
        hostile_text(),
        "[a-z0-9_-]{0,45}",
        "[0-9A-Za-z.+~_:/-]{0,70}",
        "[a-z0-9A-Z.+~_ /:-]{0,70}",
    ]
}

proptest! {
    #![proptest_config(config())]

    #[test]
    fn validated_constructors_accept_exactly_their_set(t in mostly_valid()) {
        prop_assert_eq!(CatalogId::parse(&t).is_ok(), reference_slug(&t, false, false));
        prop_assert_eq!(SetupId::parse(&t).is_ok(), reference_slug(&t, false, false));
        prop_assert_eq!(SettingId::parse(&t).is_ok(), reference_slug(&t, true, false));
        prop_assert_eq!(CallId::parse(&t).is_ok(), reference_slug(&t, true, false));
        prop_assert_eq!(HintId::parse(&t).is_ok(), reference_slug(&t, true, false));
        prop_assert_eq!(InstanceName::parse(&t).is_ok(), reference_slug(&t, false, true));
        prop_assert_eq!(PlainVersion::parse(&t).is_ok(), reference_version(&t));
        // Through JSON too: a stored or received string is checked the same way.
        let via_json = serde_json::from_str::<PlainVersion>(&json(&t)).is_ok();
        prop_assert_eq!(via_json, reference_version(&t));
        // An error names the kind, never the text.
        if let Err(e) = PlainVersion::parse(&t) {
            prop_assert!(!t.is_empty() && !e.to_string().contains(&t) || t.len() < 4);
        }
    }

    #[test]
    fn hashes_and_digests_are_exactly_lower_hex(t in "[0-9a-fA-F:sha]{0,80}") {
        let hex64 = t.len() == 64 && t.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f'));
        prop_assert_eq!(Sha256::parse(&t).is_ok(), hex64);
        let digest_ok = t.strip_prefix("sha256:").is_some_and(|rest| {
            rest.len() == 64 && rest.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f'))
        });
        prop_assert_eq!(ImageDigest::parse(&t).is_ok(), digest_ok);
    }
}

#[test]
fn epochs_are_versions_and_digests_are_not() {
    for good in ["1!2.0", "0!1.0rc1", "12!3.4+local"] {
        assert!(PlainVersion::parse(good).is_ok(), "{good}");
    }
    for bad in ["!2.0", "1!", "a!1.0", "1!2!3", "1!2 .0", "-1!2"] {
        assert!(PlainVersion::parse(bad).is_err(), "{bad}");
    }
    assert!(PlainVersion::parse(&format!("1!{}", "2".repeat(63))).is_err());
    assert!(PlainVersion::parse(&format!("1!{}", "2".repeat(62))).is_ok());
    let digest = format!("sha256:{}", "a".repeat(64));
    assert!(PlainVersion::parse(&digest).is_err());
    assert!(ImageDigest::parse(&digest).is_ok());
    assert!(ImageDigest::parse("1!2.0").is_err());
}

fn witness() -> Evidence {
    Evidence::new(
        CallId::parse("package-search").unwrap(),
        "searched every layer",
    )
}

fn is_unknown<T>(o: &Observed<T>, why: UnknownReason) -> bool {
    matches!(o, Observed::Unknown(u) if u.reason == why)
}

fn pkg_fact(presence: Observed<Presence>, v: Observed<PlainVersion>) -> Fact {
    fact(
        Subject::Service(instance("lnd")),
        Claim::Package {
            product: cat("xz-utils"),
            presence,
            version: v,
        },
    )
}

#[test]
fn absent_is_seen_only_with_complete_coverage_and_never_unknown() {
    assert!(matches!(
        Presence::absent(Coverage::Complete, witness()),
        Observed::Seen(Presence::Absent(_))
    ));
    assert!(is_unknown(
        &Presence::absent(Coverage::Partial, witness()),
        UnknownReason::IncompleteCoverage
    ));
    assert!(matches!(
        ServiceState::not_found(Coverage::Complete, witness()),
        Observed::Seen(ServiceState::NotFound(_))
    ));
    assert!(matches!(
        ServiceState::not_found(Coverage::Partial, witness()),
        Observed::Unknown(_)
    ));

    let key_in = instance("lnd");
    let product = cat("xz-utils");
    let none = || unknown::<PlainVersion>(UnknownReason::NotChecked);
    let absent = |cov| Presence::absent(cov, witness());
    let present = || Observed::Seen(Presence::Present);
    let state = |facts: &[Fact]| setup_view(facts).package(&key_in, &product);

    assert!(matches!(
        state(&[pkg_fact(absent(Coverage::Complete), none())]),
        Observed::Seen(PackageState::NotInstalled)
    ));
    // Looked, but not everywhere: unknown, never absent.
    assert!(matches!(
        state(&[pkg_fact(absent(Coverage::Partial), none())]),
        Observed::Unknown(_)
    ));
    // Never looked: unknown.
    assert!(matches!(
        state(&[pkg_fact(unknown(UnknownReason::NotChecked), none())]),
        Observed::Unknown(_)
    ));
    // Present with no readable version: installed, version unknown.
    assert!(matches!(
        state(&[pkg_fact(present(), none())]),
        Observed::Seen(PackageState::Installed(Observed::Unknown(_)))
    ));
    assert!(matches!(
        state(&[pkg_fact(present(), Observed::Seen(version("5.4.1")))]),
        Observed::Seen(PackageState::Installed(Observed::Seen(_)))
    ));
    // H1: present (version unreadable) against absent is a conflict, never "not installed".
    assert!(is_unknown(
        &state(&[
            pkg_fact(present(), none()),
            pkg_fact(absent(Coverage::Complete), none())
        ]),
        UnknownReason::Conflict
    ));
    // Present with a version against absent: a conflict.
    assert!(is_unknown(
        &state(&[
            pkg_fact(absent(Coverage::Complete), none()),
            pkg_fact(present(), Observed::Seen(version("5.4.1"))),
        ]),
        UnknownReason::Conflict
    ));
    // H1: one fact that says absent and carries a version contradicts itself.
    assert!(is_unknown(
        &state(&[pkg_fact(
            absent(Coverage::Complete),
            Observed::Seen(version("5.4.1"))
        )]),
        UnknownReason::Conflict
    ));
}

#[test]
fn absence_without_a_complete_search_cannot_be_loaded() {
    let absent = Presence::absent(Coverage::Complete, witness());
    let good = json(&absent);
    assert!(serde_json::from_str::<Observed<Presence>>(&good).is_ok());
    // Coverage changed to Partial, evidence removed, or evidence missing: refused.
    let partial = good.replace("\"Complete\"", "\"Partial\"");
    assert!(serde_json::from_str::<Observed<Presence>>(&partial).is_err());
    assert!(
        serde_json::from_str::<Observed<Presence>>(
            r#"{"Seen":{"Absent":{"coverage":"Complete"}}}"#
        )
        .is_err()
    );
    assert!(serde_json::from_str::<Observed<Presence>>(r#"{"Seen":"Absent"}"#).is_err());
    assert!(serde_json::from_str::<Observed<Presence>>(r#"{"Seen":{"Absent":null}}"#).is_err());
    let not_found = json(&ServiceState::not_found(Coverage::Complete, witness()));
    assert!(serde_json::from_str::<Observed<ServiceState>>(&not_found).is_ok());
    let partial = not_found.replace("\"Complete\"", "\"Partial\"");
    assert!(serde_json::from_str::<Observed<ServiceState>>(&partial).is_err());
    assert!(serde_json::from_str::<Observed<ServiceState>>(r#"{"Seen":"NotFound"}"#).is_err());
}

#[test]
fn a_stopped_service_is_not_running_and_a_gap_is_not_stopped() {
    let svc = |state: Observed<ServiceState>| {
        fact(
            Subject::Service(instance("lnd")),
            Claim::Service {
                state,
                version: Observed::Seen(version("1.0")),
                runs_as: container("lnd"),
                method: Method::ServiceReply,
            },
        )
    };
    let key = instance("lnd");
    let v = setup_view(&[svc(Observed::Seen(ServiceState::Stopped))]);
    assert!(matches!(
        v.state(&key),
        Observed::Seen(ServiceState::Stopped)
    ));
    let v = setup_view(&[svc(unknown(UnknownReason::NoPermission))]);
    assert!(matches!(v.state(&key), Observed::Unknown(_)));
    let v = setup_view(&[
        svc(Observed::Seen(ServiceState::Running)),
        svc(Observed::Seen(ServiceState::Stopped)),
    ]);
    assert!(is_unknown(&v.state(&key), UnknownReason::Conflict));
}

#[test]
fn a_lower_ranked_disagreement_raises_a_blind_spot_and_the_best_method_wins() {
    let ranked = |a: &str, b: &str| {
        vec![
            service_fact("lnd", a, Method::ImageDigest),
            service_fact("lnd", b, Method::ImageName),
        ]
    };
    let facts = ranked("1.0", "2.0");
    let view = setup_view(&facts);
    assert!(matches!(&view.service(&instance("lnd")), Observed::Seen(v) if v.as_str() == "1.0"));
    assert_eq!(view.blind_spots.len(), 1);
    assert!(matches!(
        view.blind_spots[0].what,
        BlindSpotKind::MethodsDisagree
    ));
    // Agreement raises nothing; order never matters.
    assert!(setup_view(&ranked("1.0", "1.0")).blind_spots.is_empty());
    let mut reversed = facts.clone();
    reversed.reverse();
    assert_eq!(render(&setup_view(&reversed)), render(&view));
    assert_eq!(setup_view(&reversed).blind_spots, view.blind_spots);
    // A disagreement at the top rank is a conflict, and not a blind spot.
    let tie = setup_view(&[
        service_fact("lnd", "1.0", Method::ImageDigest),
        service_fact("lnd", "2.0", Method::ImageDigest),
    ]);
    assert!(is_unknown(
        &tie.service(&instance("lnd")),
        UnknownReason::Conflict
    ));
    assert!(tie.blind_spots.is_empty());
}

#[test]
fn a_better_methods_conflict_or_silence_is_never_replaced_quietly() {
    let with_version = |v: Observed<PlainVersion>, method| {
        fact(
            Subject::Service(instance("lnd")),
            Claim::Service {
                state: Observed::Seen(ServiceState::Running),
                version: v,
                runs_as: container("lnd"),
                method,
            },
        )
    };
    let reply = || with_version(Observed::Seen(version("1.0")), Method::ServiceReply);
    // L1: the digest method disagreed with itself; the self-report must not win.
    let v = setup_view(&[
        with_version(unknown(UnknownReason::Conflict), Method::ImageDigest),
        reply(),
    ]);
    assert!(is_unknown(
        &v.service(&instance("lnd")),
        UnknownReason::Conflict
    ));
    // A worse method's conflict doesn't override a better method's answer.
    let v = setup_view(&[
        with_version(Observed::Seen(version("2.0")), Method::ImageDigest),
        with_version(unknown(UnknownReason::Conflict), Method::ImageName),
    ]);
    assert!(matches!(&v.service(&instance("lnd")), Observed::Seen(x) if x.as_str() == "2.0"));
    // A better method with no answer: the weaker version is used, with a blind spot.
    let v = setup_view(&[
        with_version(unknown(UnknownReason::NoPermission), Method::ImageDigest),
        reply(),
    ]);
    assert!(matches!(&v.service(&instance("lnd")), Observed::Seen(x) if x.as_str() == "1.0"));
    assert_eq!(v.blind_spots.len(), 1);
    assert!(matches!(
        v.blind_spots[0].what,
        BlindSpotKind::BetterMethodUnavailable
    ));
}

#[test]
fn a_missing_key_is_unknown_never_none() {
    let v = setup_view(&[service_fact("lnd", "1.0", Method::ServiceReply)]);
    let ghost = instance("strfry");
    assert!(is_unknown(&v.service(&ghost), UnknownReason::NotChecked));
    assert!(is_unknown(&v.state(&ghost), UnknownReason::NotChecked));
    assert!(is_unknown(
        &v.package(&ghost, &cat("xz-utils")),
        UnknownReason::NotChecked
    ));
    assert!(is_unknown(
        &v.setting(&SettingId::parse("option_enabled").unwrap()),
        UnknownReason::NotChecked
    ));
}

#[test]
fn a_claim_on_the_wrong_subject_is_a_blind_spot_not_silence() {
    let service_on_host = fact(
        Subject::Host,
        Claim::Service {
            state: Observed::Seen(ServiceState::Running),
            version: Observed::Seen(version("1.0")),
            runs_as: container("lnd"),
            method: Method::Port,
        },
    );
    let package_on_setup = fact(
        Subject::Setup,
        Claim::Package {
            product: cat("xz-utils"),
            presence: Observed::Seen(Presence::Present),
            version: unknown(UnknownReason::NotChecked),
        },
    );
    let v = setup_view(&[service_on_host.clone(), service_on_host, package_on_setup]);
    assert_eq!(v.blind_spots.len(), 2, "{:?}", v.blind_spots);
    assert!(
        v.blind_spots
            .iter()
            .all(|s| matches!(s.what, BlindSpotKind::WrongSubject))
    );
    assert!(is_unknown(
        &v.state(&instance("lnd")),
        UnknownReason::NotChecked
    ));
}

#[test]
fn containers_not_checked_is_a_blind_spot_that_round_trips() {
    let f = fact(
        Subject::Host,
        Claim::BlindSpot {
            area: Area::Containers,
            what: BlindSpotKind::NotChecked,
            hint: HintId::parse("containers-not-checked").unwrap(),
        },
    );
    assert_eq!(f.claim.kind(), "blind_spot");
    let back: Fact = serde_json::from_str(&json(&f)).unwrap();
    assert!(matches!(
        back.claim,
        Claim::BlindSpot {
            area: Area::Containers,
            what: BlindSpotKind::NotChecked,
            ..
        }
    ));
}

#[test]
fn an_unrecognized_service_on_a_known_port_blocks_a_claim_of_absence() {
    let lnd = instance("lnd");
    let unrecognized = |candidates: Vec<CatalogId>| {
        fact(
            Subject::Host,
            Claim::Unrecognized {
                candidates,
                runs_as: container("mystery"),
                version_label: None,
                source_label: None,
            },
        )
    };
    let lnd_not_found = || {
        fact(
            Subject::Service(lnd.clone()),
            Claim::Service {
                state: ServiceState::not_found(Coverage::Complete, witness()),
                version: unknown(UnknownReason::NotChecked),
                runs_as: container("lnd"),
                method: Method::Port,
            },
        )
    };
    let lnd_package_absent = || {
        fact(
            Subject::Service(instance("bitcoin-core")),
            Claim::Package {
                product: cat("lnd"),
                presence: Presence::absent(Coverage::Complete, witness()),
                version: unknown(UnknownReason::NotChecked),
            },
        )
    };
    let key = (instance("bitcoin-core"), cat("lnd"));

    // Without the unrecognised endpoint, absence stands.
    let plain = setup_view(&[lnd_not_found(), lnd_package_absent()]);
    assert!(matches!(
        plain.state(&lnd),
        Observed::Seen(ServiceState::NotFound(_))
    ));
    assert!(matches!(
        plain.package(&key.0, &key.1),
        Observed::Seen(PackageState::NotInstalled)
    ));
    // An unrecognised service on LND's port makes lnd Unknown, never absent.
    let facts = [
        lnd_not_found(),
        lnd_package_absent(),
        unrecognized(vec![cat("lnd")]),
    ];
    let v = setup_view(&facts);
    assert!(is_unknown(&v.state(&lnd), UnknownReason::Unidentified));
    assert!(is_unknown(
        &v.package(&key.0, &key.1),
        UnknownReason::Unidentified
    ));
    // Candidates for another product leave lnd's absence alone.
    let other = setup_view(&[
        lnd_not_found(),
        lnd_package_absent(),
        unrecognized(vec![cat("strfry")]),
    ]);
    assert!(matches!(
        other.state(&lnd),
        Observed::Seen(ServiceState::NotFound(_))
    ));
    // Order never matters.
    let mut reversed = facts.to_vec();
    reversed.reverse();
    assert_eq!(render(&setup_view(&reversed)), render(&v));
}

#[test]
fn settings_are_read_from_facts_and_gaps_are_unknown() {
    let id = |s: &str| SettingId::parse(s).unwrap();
    let setting = |key: &str, value: Observed<SettingValue>| {
        fact(
            Subject::Service(instance("bitcoin-core")),
            Claim::Setting {
                key: id(key),
                value,
            },
        )
    };
    let v = setup_view(&[
        setting("option_enabled", Observed::Seen(SettingValue::Enabled)),
        setting("option_disabled", Observed::Seen(SettingValue::Disabled)),
        setting(
            "backend_in_use",
            Observed::Seen(SettingValue::Named(id("leveldb"))),
        ),
        setting(
            "node_builds_block_templates",
            unknown(UnknownReason::NotChecked),
        ),
        // Two facts that disagree: a conflict.
        setting("feature_enabled", Observed::Seen(SettingValue::Enabled)),
        setting("feature_enabled", Observed::Seen(SettingValue::Disabled)),
    ]);
    assert!(matches!(
        v.setting(&id("option_enabled")),
        Observed::Seen(SettingValue::Enabled)
    ));
    assert!(matches!(
        v.setting(&id("option_disabled")),
        Observed::Seen(SettingValue::Disabled)
    ));
    assert!(matches!(
        v.setting(&id("backend_in_use")),
        Observed::Seen(SettingValue::Named(_))
    ));
    assert!(is_unknown(
        &v.setting(&id("node_builds_block_templates")),
        UnknownReason::NotChecked
    ));
    assert!(is_unknown(
        &v.setting(&id("feature_enabled")),
        UnknownReason::Conflict
    ));
    // Never mentioned: Unknown(NotChecked), not "disabled".
    assert!(is_unknown(
        &v.setting(&id("option_never_asked")),
        UnknownReason::NotChecked
    ));
    assert_eq!(v.settings().count(), 5);
}

#[test]
fn named_bad_ids_and_versions_are_refused() {
    for bad in [
        "",
        "Bitcoin",
        "-core",
        "a b",
        "a/b",
        "../x",
        "a\n",
        "a\u{0}",
        "bitcoin_core",
        "é",
        &"a".repeat(41),
    ] {
        assert!(CatalogId::parse(bad).is_err(), "catalog id {bad:?}");
    }
    for bad in [
        "",
        "1.0\n",
        "1.0 ",
        "v1;rm",
        "1.0/2",
        "\u{202e}1.0",
        "١.٠",
        &"1".repeat(65),
    ] {
        assert!(PlainVersion::parse(bad).is_err(), "version {bad:?}");
    }
    for good in [
        "32.1",
        "0.21.6-beta",
        "1.1.2-148-g4cd3cf6",
        "5.4.1-1+deb12u2",
        "1~rc1",
    ] {
        assert!(PlainVersion::parse(good).is_ok(), "version {good:?}");
    }
    assert!(CatalogId::parse(&"a".repeat(40)).is_ok());
    assert!(PlainVersion::parse(&"1".repeat(64)).is_ok());
    assert!(InstanceName::parse("").is_ok());
    assert!(SettingId::parse("option_enabled").is_ok());
    assert_eq!(
        PlainVersion::parse("bad one").unwrap_err().to_string(),
        "not a valid version"
    );
    // A planted bad id inside a stored fact is refused on load.
    let ok = json(&fact(
        Subject::Host,
        Claim::Platform {
            id: cat("docker"),
            version: unknown(UnknownReason::NotChecked),
        },
    ));
    assert!(serde_json::from_str::<Fact>(&ok).is_ok());
    let bad = ok.replace("\"docker\"", "\"dock er\"");
    assert!(serde_json::from_str::<Fact>(&bad).is_err());
}

// ------------------------------------------------------ evidence limits

proptest! {
    #![proptest_config(config())]

    #[test]
    fn evidence_is_cut_visibly_at_a_character_boundary(
        text in prop_oneof![hostile_text(), "[a-zé🐕]{0,2500}"]
    ) {
        let e = Evidence::new(CallId::parse("c").unwrap(), &text);
        let kept = e.raw().expose_untrusted().clone(); // test reads its own value
        prop_assert!(kept.len() <= MAX_EVIDENCE_BYTES);
        if text.len() <= MAX_EVIDENCE_BYTES {
            prop_assert_eq!(&kept, &text);
        } else {
            prop_assert!(kept.ends_with(CUT_MARKER));
            let head = &kept[..kept.len() - CUT_MARKER.len()];
            prop_assert!(text.starts_with(head));
        }
        // Cutting twice changes nothing, and what we stored loads back.
        prop_assert_eq!(&Evidence::new(CallId::parse("c").unwrap(), &kept).raw().expose_untrusted().clone(), &kept);
        let back: Evidence = serde_json::from_str(&json(&e)).unwrap();
        prop_assert_eq!(back.raw().byte_len(), kept.len());
    }
}

#[test]
fn too_much_evidence_is_dropped_and_oversized_evidence_is_refused_on_load() {
    let five = (0..5)
        .map(|i| Evidence::new(CallId::parse("c").unwrap(), &format!("reply {i}")))
        .collect();
    let f = Fact::new(
        Subject::Host,
        Claim::Chain(unknown(UnknownReason::NoReply)),
        source(SensorId::BitcoindRpc),
        Timestamp(0),
        five,
    )
    .unwrap();
    assert_eq!(f.evidence().len(), MAX_EVIDENCE);

    let big = format!(
        r#"{{"call":"c","raw":{{"untrusted":"{}"}}}}"#,
        "x".repeat(2000)
    );
    assert!(serde_json::from_str::<Evidence>(&big).is_err());
    // A fact stored with five items loads with four.
    let mut doc: Json = serde_json::from_str(&json(&f)).unwrap();
    let item = doc["evidence"][0].clone();
    doc["evidence"].as_array_mut().unwrap().push(item.clone());
    doc["evidence"].as_array_mut().unwrap().push(item);
    let loaded: Fact = serde_json::from_value(doc).unwrap();
    assert_eq!(loaded.evidence().len(), MAX_EVIDENCE);
}

// ----------------------------------------------------- method order, model

#[test]
fn digests_and_signed_hashes_outrank_self_reports() {
    use Method::*;
    let order = [
        SignedHash,
        ImageDigest,
        ServiceReply,
        ImageName,
        Binary,
        Unit,
        Port,
        UserEntered,
    ];
    for pair in order.windows(2) {
        assert!(
            pair[0].outranks(pair[1]),
            "{:?} over {:?}",
            pair[0],
            pair[1]
        );
        assert!(!pair[1].outranks(pair[0]));
    }
    let mut shuffled = [
        Port,
        SignedHash,
        UserEntered,
        ServiceReply,
        Unit,
        ImageDigest,
        Binary,
        ImageName,
    ];
    shuffled.sort();
    assert_eq!(shuffled, order);
    assert_eq!(FACT_MODEL, 1);
}

#[test]
fn a_digest_beats_a_self_report_in_the_view() {
    let facts = [
        service_fact("lnd", "0.18.4-beta", Method::ServiceReply),
        service_fact("lnd", "0.21.6-beta", Method::ImageDigest),
    ];
    let view = setup_view(&facts);
    match &view.service(&instance("lnd")) {
        Observed::Seen(v) => assert_eq!(v.as_str(), "0.21.6-beta"),
        Observed::Unknown(_) => panic!("expected the digest's version"),
    }
    // Two equally good sources that disagree are a conflict, not a pick.
    let tie = [
        service_fact("lnd", "1.0", Method::ServiceReply),
        service_fact("lnd", "2.0", Method::ServiceReply),
    ];
    assert!(matches!(
        &setup_view(&tie).service(&instance("lnd")),
        Observed::Unknown(Unknown {
            reason: UnknownReason::Conflict,
            ..
        })
    ));
}

// -------------------------- every Judge B family and manifest kind has a claim

const NODE: &str = "bitcoin-core";

fn fs_from(label: &str) -> FsKind {
    match label {
        "tmpfs" => FsKind::Tmpfs,
        "ext4" => FsKind::Ext4,
        "fat32" => FsKind::Fat32,
        "btrfs" => FsKind::Btrfs,
        "xfs" => FsKind::Xfs,
        "zfs" => FsKind::Zfs,
        other => panic!("fixture block_storage {other:?} has no FsKind in this test"),
    }
}

fn fs_label(kind: &FsKind) -> &'static str {
    match kind {
        FsKind::Tmpfs => "tmpfs",
        FsKind::Ext4 => "ext4",
        FsKind::Fat32 => "fat32",
        FsKind::Btrfs => "btrfs",
        FsKind::Xfs => "xfs",
        FsKind::Zfs => "zfs",
        _ => "other",
    }
}

fn chain_from(label: &str) -> Chain {
    match label {
        "main" => Chain::Main,
        "testnet3" => Chain::Testnet3,
        "testnet4" => Chain::Testnet4,
        "signet" => Chain::Signet,
        "regtest" => Chain::Regtest,
        other => panic!("chain {other:?}"),
    }
}

fn chain_label(chain: Chain) -> &'static str {
    match chain {
        Chain::Main => "main",
        Chain::Testnet3 => "testnet3",
        Chain::Testnet4 => "testnet4",
        Chain::Signet => "signet",
        Chain::Regtest => "regtest",
    }
}

fn backend_from(source_label: &str, setup: &str) -> Backend {
    let setup = SetupId::parse(setup).unwrap();
    match source_label {
        "lab" => Backend::Recorded { setup },
        "synthetic" => Backend::Fixture { setup },
        other => panic!("source {other:?}"),
    }
}

/// Judge B's view of a setup, as `family -> text`, read back out of a
/// [`SetupView`] the way the two-back-ends judge will.
fn judge_text(view: &SetupView) -> Vec<(String, String)> {
    fn seen<T>(o: &Observed<T>, f: impl Fn(&T) -> String) -> String {
        match o {
            Observed::Seen(v) => f(v),
            Observed::Unknown(u) => format!("unknown ({:?})", u.reason),
        }
    }
    let mut out = vec![
        (
            "source".to_owned(),
            seen(&view.source, |s| match s {
                BackendKind::Recorded => "lab".to_owned(),
                BackendKind::Fixture => "synthetic".to_owned(),
                BackendKind::Live => "live".to_owned(),
                BackendKind::Fake => "fake".to_owned(),
            }),
        ),
        (
            "chain".to_owned(),
            seen(&view.chain, |c| chain_label(*c).to_owned()),
        ),
        (
            "platform".to_owned(),
            seen(&view.platform, |p| p.as_str().to_owned()),
        ),
        (
            "arch".to_owned(),
            seen(&view.word_size, |w| match w {
                WordSize::Bits64 => "64-bit".to_owned(),
                WordSize::Bits32 => "32-bit".to_owned(),
            }),
        ),
        (
            "block_storage".to_owned(),
            seen(&view.block_storage, |k| fs_label(k).to_owned()),
        ),
        (
            "exposure".to_owned(),
            seen(&view.exposure, |r| {
                match r {
                    Reach::NotListening | Reach::Localhost => "none",
                    Reach::Lan => "lan",
                    Reach::Tunnel => "tunnel",
                    Reach::Internet => "internet",
                }
                .to_owned()
            }),
        ),
    ];
    for (inst, v) in view.services() {
        out.push((
            format!("service {}", inst.catalog.as_str()),
            seen(v, |v| v.as_str().to_owned()),
        ));
    }
    for ((inst, product), v) in view.packages() {
        out.push((
            format!("package {} {}", inst.catalog.as_str(), product.as_str()),
            seen(v, |s| match s {
                PackageState::NotInstalled => "none".to_owned(),
                PackageState::Installed(Observed::Seen(v)) => v.as_str().to_owned(),
                PackageState::Installed(Observed::Unknown(_)) => {
                    "installed, version unknown".to_owned()
                }
            }),
        ));
    }
    out.sort();
    out
}

/// A `[[setup]]` of `expected-matches.toml` as facts, one claim per family.
fn facts_from_fixture(setup: &Table) -> Vec<Fact> {
    let text = |t: &Table, k: &str| t[k].as_str().unwrap().to_owned();
    let id = text(setup, "id");
    let backend = backend_from(&text(setup, "source"), &id);
    let method = if text(setup, "source") == "lab" {
        Method::ServiceReply
    } else {
        Method::UserEntered
    };
    let mk = |subject: Subject, claim: Claim| {
        Fact::new(
            subject,
            claim,
            Source {
                sensor: SensorId::Fixture,
                backend: backend.clone(),
            },
            Timestamp(1),
            vec![],
        )
        .unwrap()
    };
    let node = Subject::Service(instance(NODE));
    let mut facts = vec![
        mk(
            node.clone(),
            Claim::Chain(Observed::Seen(chain_from(&text(setup, "chain")))),
        ),
        mk(
            Subject::Host,
            Claim::Platform {
                id: cat(&text(setup, "platform")),
                version: unknown(UnknownReason::NotChecked),
            },
        ),
        mk(
            Subject::Host,
            Claim::Host {
                os: OutsideText::new("fixture"),
                os_version: unknown(UnknownReason::NotChecked),
                kernel: unknown(UnknownReason::NotChecked),
                arch: Observed::Seen(match text(setup, "arch").as_str() {
                    "64-bit" => Arch::Aarch64,
                    "32-bit" => Arch::Armv7,
                    other => panic!("arch {other:?}"),
                }),
            },
        ),
        mk(
            node.clone(),
            Claim::BlockStorage(Observed::Seen(fs_from(&text(setup, "block_storage")))),
        ),
        mk(
            node,
            Claim::Exposure {
                port: 8333,
                proto: Proto::Tcp,
                reach: Observed::Seen(match text(setup, "exposure").as_str() {
                    "none" => Reach::NotListening,
                    "lan" => Reach::Lan,
                    "tunnel" => Reach::Tunnel,
                    "internet" => Reach::Internet,
                    other => panic!("exposure {other:?}"),
                }),
            },
        ),
    ];
    for svc in setup["service"].as_array().unwrap() {
        let svc = svc.as_table().unwrap();
        facts.push(mk(
            Subject::Service(instance(&text(svc, "id"))),
            Claim::Service {
                state: Observed::Seen(ServiceState::Running),
                version: Observed::Seen(version(&text(svc, "version"))),
                runs_as: container(&text(svc, "id")),
                method,
            },
        ));
    }
    for pkg in setup
        .get("package")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let pkg = pkg.as_table().unwrap();
        let (presence, found) = match text(pkg, "version").as_str() {
            // The fixture's `none` is a complete search that found nothing.
            "none" => (
                Presence::absent(Coverage::Complete, witness()),
                unknown(UnknownReason::NotChecked),
            ),
            v => (
                Observed::Seen(Presence::Present),
                Observed::Seen(version(v)),
            ),
        };
        facts.push(mk(
            Subject::Service(instance(&text(pkg, "in"))),
            Claim::Package {
                product: cat(&text(pkg, "product")),
                presence,
                version: found,
            },
        ));
    }
    facts
}

/// What the fixture says, in `judge_text`'s shape.
fn fixture_text(setup: &Table) -> Vec<(String, String)> {
    let text = |t: &Table, k: &str| t[k].as_str().unwrap().to_owned();
    let mut out: Vec<(String, String)> = [
        "arch",
        "block_storage",
        "chain",
        "exposure",
        "platform",
        "source",
    ]
    .iter()
    .map(|k| ((*k).to_owned(), text(setup, k)))
    .collect();
    for svc in setup["service"].as_array().unwrap() {
        let svc = svc.as_table().unwrap();
        out.push((format!("service {}", text(svc, "id")), text(svc, "version")));
    }
    for pkg in setup
        .get("package")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let pkg = pkg.as_table().unwrap();
        out.push((
            format!("package {} {}", text(pkg, "in"), text(pkg, "product")),
            text(pkg, "version"),
        ));
    }
    out.sort();
    out
}

fn fixture_setups() -> Vec<Table> {
    let doc: Table = toml::from_str(&read("fixtures/expected-matches.toml")).unwrap();
    doc["setup"]
        .as_array()
        .unwrap()
        .iter()
        .map(|s| s.as_table().unwrap().clone())
        .collect()
}

#[test]
fn every_judge_b_family_is_a_fact_and_comes_back_equal() {
    let setups = fixture_setups();
    assert!(setups.len() >= 2);
    for setup in &setups {
        let facts = facts_from_fixture(setup);
        let kinds: BTreeSet<&str> = facts.iter().map(|f| f.claim.kind()).collect();
        for needed in [
            "chain",
            "platform",
            "host",
            "block_storage",
            "exposure",
            "service",
        ] {
            assert!(kinds.contains(needed), "{}: no {needed} claim", setup["id"]);
        }
        // lab-old-synthetic has no packages (no images), so it has seven families.
        let has_packages = setup.contains_key("package");
        assert_eq!(kinds.contains("package"), has_packages, "{}", setup["id"]);
        // All eight families two_backends.rs lists: arch, block_storage, chain, exposure,
        // package, platform, service, source.
        let families: BTreeSet<String> = fixture_text(setup)
            .iter()
            .map(|(k, _)| k.split(' ').next().unwrap().to_owned())
            .collect();
        let expected: Vec<&str> = [
            "arch",
            "block_storage",
            "chain",
            "exposure",
            "package",
            "platform",
            "service",
            "source",
        ]
        .into_iter()
        .filter(|f| has_packages || *f != "package")
        .collect();
        assert_eq!(
            families.iter().map(String::as_str).collect::<Vec<_>>(),
            expected
        );
        // Stored and loaded (through JSON) before folding, as the store will.
        let reloaded: Vec<Fact> = facts
            .iter()
            .map(|f| serde_json::from_str(&json(f)).unwrap())
            .collect();
        assert_eq!(
            judge_text(&setup_view(&reloaded)),
            fixture_text(setup),
            "setup {}",
            setup["id"]
        );
    }
}

const MANIFEST_FACT_KINDS: [&str; 7] = [
    "arch",
    "block_storage",
    "chain",
    "exposure",
    "platform",
    "service",
    "source",
];
const MANIFEST_NOTES: [&str; 3] = ["description", "format", "recorder"];

#[test]
fn every_lab_manifest_kind_is_a_fact_and_comes_back_equal() {
    let m: Table = toml::from_str(&read("fixtures/lab-recorded/manifest.toml")).unwrap();
    // A new manifest key must be added to one of the two lists on purpose.
    let keys: BTreeSet<&str> = m.keys().map(String::as_str).collect();
    let known: BTreeSet<&str> = MANIFEST_FACT_KINDS
        .iter()
        .chain(&MANIFEST_NOTES)
        .copied()
        .collect();
    assert_eq!(
        keys, known,
        "the manifest has a kind this test doesn't know"
    );

    let text = |t: &Table, k: &str| t[k].as_str().unwrap().to_owned();
    let backend = backend_from(&text(&m, "source"), "lab-regtest");
    let mk = |subject: Subject, claim: Claim| {
        Fact::new(
            subject,
            claim,
            Source {
                sensor: SensorId::LabManifest,
                backend: backend.clone(),
            },
            Timestamp(1),
            vec![],
        )
        .unwrap()
    };
    let mut facts = vec![
        mk(
            Subject::Service(instance(NODE)),
            Claim::Chain(Observed::Seen(chain_from(&text(&m, "chain")))),
        ),
        mk(
            Subject::Host,
            Claim::Platform {
                id: cat(&text(&m, "platform")),
                version: unknown(UnknownReason::NotChecked),
            },
        ),
    ];
    for svc in m["service"].as_array().unwrap() {
        let svc = svc.as_table().unwrap();
        facts.push(mk(
            Subject::Service(instance(&text(svc, "id"))),
            Claim::Service {
                state: Observed::Seen(ServiceState::Running),
                version: Observed::Seen(version(&text(svc, "version"))),
                runs_as: container(&text(svc, "id")),
                method: Method::ServiceReply,
            },
        ));
    }
    // Without the three derived kinds, the view says Unknown, never a guess.
    let without = judge_text(&setup_view(&facts));
    for family in ["arch", "block_storage", "exposure"] {
        let (_, value) = without.iter().find(|(f, _)| f == family).unwrap();
        assert!(value.starts_with("unknown"), "{family}: {value}");
    }
    facts.push(mk(
        Subject::Host,
        Claim::Host {
            os: OutsideText::new("lab"),
            os_version: unknown(UnknownReason::NotChecked),
            kernel: unknown(UnknownReason::NotChecked),
            arch: Observed::Seen(match text(&m, "arch").as_str() {
                "64-bit" => Arch::Aarch64,
                other => panic!("arch {other:?}"),
            }),
        },
    ));
    facts.push(mk(
        Subject::Service(instance(NODE)),
        Claim::BlockStorage(Observed::Seen(fs_from(&text(&m, "block_storage")))),
    ));
    facts.push(mk(
        Subject::Service(instance(NODE)),
        Claim::Exposure {
            port: 8333,
            proto: Proto::Tcp,
            reach: Observed::Seen(match text(&m, "exposure").as_str() {
                "none" => Reach::NotListening,
                other => panic!("exposure {other:?}"),
            }),
        },
    ));

    // The manifest's `source` is the fact's Backend: every fact carries it.
    assert!(
        facts
            .iter()
            .all(|f| matches!(f.source.backend, Backend::Recorded { .. }))
    );

    let view = judge_text(&setup_view(&facts));
    for (family, value) in [
        ("chain", text(&m, "chain")),
        ("platform", text(&m, "platform")),
        ("source", text(&m, "source")),
        ("arch", text(&m, "arch")),
        ("block_storage", text(&m, "block_storage")),
        ("exposure", text(&m, "exposure")),
    ] {
        assert!(view.contains(&(family.to_owned(), value)), "{family}");
    }
    for svc in m["service"].as_array().unwrap() {
        let svc = svc.as_table().unwrap();
        assert!(view.contains(&(format!("service {}", text(svc, "id")), text(svc, "version"))));
    }
}

fn condition_names(value: &Json, out: &mut BTreeSet<String>) {
    match value {
        Json::Object(map) => {
            for (k, v) in map {
                if k == "fact"
                    && let Some(name) = v.as_str()
                {
                    out.insert(name.to_owned());
                }
                condition_names(v, out);
            }
        }
        Json::Array(items) => items.iter().for_each(|v| condition_names(v, out)),
        _ => {}
    }
}

/// Corpus condition names that are Settings for now; Phase 2.2 gives each its
/// real mapping, and `hardware_model` waits for registered things (1.5).
const SETTING_ONLY: &[&str] = &[
    "accepts_inbound_p2p",
    "hardware_model",
    "multi_store_server",
    "node_builds_block_templates",
    "owner_may_open_untrusted_links",
    "p2p_inbound_or_outbound_peers",
    "payment_state_trusted_for_fulfilment",
    "seed_built_with_50_or_more_dice_rolls",
    "seed_generated_on_firmware_in_range",
    "web_ui_reachable_from_internet",
];

#[test]
fn every_advisory_condition_fact_has_a_claim() {
    let mut names = BTreeSet::new();
    let dir = root().join("advisories/corpus");
    for entry in fs::read_dir(dir).unwrap() {
        let path = entry.unwrap().path();
        if path.extension().is_some_and(|e| e == "json") {
            condition_names(
                &serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap(),
                &mut names,
            );
        }
    }
    assert!(names.len() >= 15, "found only {names:?}");

    let id = |s: &str| SettingId::parse(s).unwrap();
    let mut direct: Vec<(&str, Claim)> = vec![
        (
            "service_running",
            Claim::Service {
                state: Observed::Seen(ServiceState::Running),
                version: unknown(UnknownReason::NotChecked),
                runs_as: container("x"),
                method: Method::Port,
            },
        ),
        (
            "package_installed",
            Claim::Package {
                product: cat("xz-utils"),
                presence: unknown(UnknownReason::NotChecked),
                version: unknown(UnknownReason::NotChecked),
            },
        ),
        (
            "platform",
            Claim::Platform {
                id: cat("umbrelos"),
                version: unknown(UnknownReason::NotChecked),
            },
        ),
        (
            "port_exposed_to_internet",
            Claim::Exposure {
                port: 9735,
                proto: Proto::Tcp,
                reach: Observed::Seen(Reach::Internet),
            },
        ),
    ];
    for name in [
        "option_enabled",
        "option_disabled",
        "backend_in_use",
        "feature_enabled",
    ] {
        direct.push((
            name,
            Claim::Setting {
                key: id(name),
                value: Observed::Seen(SettingValue::Enabled),
            },
        ));
    }
    let direct_names: BTreeSet<&str> = direct.iter().map(|(n, _)| *n).collect();
    for (name, claim) in &direct {
        assert!(names.contains(*name), "corpus no longer uses {name}");
        assert!(!claim.kind().is_empty());
    }
    // Pinned: a new condition name must be added here on purpose, either mapped
    // above or listed as a Setting (hardware_model needs Subject::Registered, 1.5).
    let rest: BTreeSet<&str> = names
        .iter()
        .map(String::as_str)
        .filter(|n| !direct_names.contains(n))
        .collect();
    let pinned: BTreeSet<&str> = SETTING_ONLY.iter().copied().collect();
    assert_eq!(rest, pinned, "update SETTING_ONLY");
    // Every other condition is a Setting keyed by its own name, until Phase 2.2
    // gives it a richer claim.
    for name in names.iter().filter(|n| !direct_names.contains(n.as_str())) {
        let claim = Claim::Setting {
            key: SettingId::parse(name).unwrap(),
            value: Observed::Seen(SettingValue::Disabled),
        };
        assert_eq!(claim.kind(), "setting");
    }
}

// ------------------------------------------------- derived views are stable

proptest! {
    #![proptest_config(config())]

    #[test]
    fn the_view_is_the_same_whatever_order_facts_arrive_in(
        shuffled in {
            let setups = fixture_setups();
            let mut facts = Vec::new();
            for setup in &setups {
                facts.extend(facts_from_fixture(setup));
            }
            // Add disagreements and unknowns so the fold has real work to do.
            facts.push(fact(Subject::Service(instance("lnd")), Claim::Chain(Observed::Seen(Chain::Signet))));
            facts.push(service_fact("lnd", "9.9", Method::ImageName));
            facts.push(fact(Subject::Host, Claim::Exposure { port: 1, proto: Proto::Udp, reach: unknown(UnknownReason::NoPermission) }));
            Just(facts).prop_shuffle()
        }
    ) {
        let reference = {
            let mut sorted: Vec<Fact> = shuffled.clone();
            sorted.sort_by_key(json);
            render(&setup_view(&sorted))
        };
        prop_assert_eq!(render(&setup_view(&shuffled)), reference);
    }
}

#[test]
fn disagreements_and_gaps_are_unknown_never_a_pick() {
    let chain = |c| {
        fact(
            Subject::Service(instance("lnd")),
            Claim::Chain(Observed::Seen(c)),
        )
    };
    let host = |a: Arch| {
        fact(
            Subject::Host,
            Claim::Host {
                os: OutsideText::new("x"),
                os_version: unknown(UnknownReason::NotChecked),
                kernel: unknown(UnknownReason::NotChecked),
                arch: Observed::Seen(a),
            },
        )
    };

    let v = setup_view(&[chain(Chain::Main), chain(Chain::Regtest)]);
    assert!(matches!(
        v.chain,
        Observed::Unknown(Unknown {
            reason: UnknownReason::Conflict,
            ..
        })
    ));
    let v = setup_view(&[host(Arch::X86_64), host(Arch::Armv7)]);
    assert!(matches!(
        v.word_size,
        Observed::Unknown(Unknown {
            reason: UnknownReason::Conflict,
            ..
        })
    ));
    // x86_64 and aarch64 are both 64-bit: no conflict.
    let v = setup_view(&[host(Arch::X86_64), host(Arch::Aarch64)]);
    assert!(matches!(v.word_size, Observed::Seen(WordSize::Bits64)));
    // An architecture we don't know has no word size.
    let v = setup_view(&[host(Arch::Other(OutsideText::new("riscv")))]);
    assert!(matches!(
        v.word_size,
        Observed::Unknown(Unknown {
            reason: UnknownReason::Unparsable,
            ..
        })
    ));
    // No facts at all: nothing is claimed.
    let v = setup_view(&[]);
    assert!(matches!(
        v.chain,
        Observed::Unknown(Unknown {
            reason: UnknownReason::NotChecked,
            ..
        })
    ));
    assert!(matches!(
        v.exposure,
        Observed::Unknown(Unknown {
            reason: UnknownReason::NotChecked,
            ..
        })
    ));
    assert!(v.services().next().is_none() && v.packages().next().is_none());
}

fn reach_facts(items: &[Observed<Reach>]) -> Vec<Fact> {
    items
        .iter()
        .enumerate()
        .map(|(i, reach)| {
            fact(
                Subject::Host,
                Claim::Exposure {
                    port: 1000 + i as u16,
                    proto: Proto::Tcp,
                    reach: reach.clone(),
                },
            )
        })
        .collect()
}

fn any_reach() -> impl Strategy<Value = Observed<Reach>> {
    prop_oneof![
        Just(Observed::Seen(Reach::NotListening)),
        Just(Observed::Seen(Reach::Localhost)),
        Just(Observed::Seen(Reach::Lan)),
        Just(Observed::Seen(Reach::Tunnel)),
        Just(Observed::Seen(Reach::Internet)),
        Just(unknown(UnknownReason::NotChecked)),
        Just(unknown(UnknownReason::NoPermission)),
    ]
}

proptest! {
    #![proptest_config(config())]

    /// Replacing any one exposure fact with Unknown never makes the setup look
    /// safer: the answer is the same as before, or Unknown, never a narrower Seen.
    #[test]
    fn unknown_never_moves_exposure_towards_none(
        items in proptest::collection::vec(any_reach(), 1..8),
        at in 0usize..8,
    ) {
        let at = at % items.len();
        let before = setup_view(&reach_facts(&items)).exposure;
        let mut changed = items.clone();
        changed[at] = unknown(UnknownReason::NotChecked);
        let after = setup_view(&reach_facts(&changed)).exposure;
        match after {
            Observed::Unknown(_) => {}
            Observed::Seen(r) => match before {
                Observed::Seen(b) => prop_assert_eq!(r, b),
                Observed::Unknown(_) => prop_assert!(false, "Unknown turned into Seen({r:?})"),
            },
        }
    }

    /// A port nobody checked can't be reported as "none".
    #[test]
    fn an_unchecked_port_blocks_a_none_answer(items in proptest::collection::vec(any_reach(), 1..8)) {
        let view = setup_view(&reach_facts(&items));
        let has_unknown = items.iter().any(|o| matches!(o, Observed::Unknown(_)));
        let has_internet = items.iter().any(|o| matches!(o, Observed::Seen(Reach::Internet)));
        if has_unknown && !has_internet {
            prop_assert!(matches!(view.exposure, Observed::Unknown(_)));
        }
    }
}

#[test]
fn no_exposure_evidence_is_not_checked_never_none() {
    assert!(matches!(
        setup_view(&[]).exposure,
        Observed::Unknown(Unknown {
            reason: UnknownReason::NotChecked,
            ..
        })
    ));
}

// ------------------------------------------------ the version character set

#[test]
fn every_version_in_the_fixtures_parses_and_up_sh_only_text_is_refused() {
    let mut versions = Vec::new();
    let m: Table = toml::from_str(&read("fixtures/lab-recorded/manifest.toml")).unwrap();
    for svc in m["service"].as_array().unwrap() {
        versions.push(svc["version"].as_str().unwrap().to_owned());
    }
    for setup in fixture_setups() {
        for svc in setup["service"].as_array().unwrap() {
            versions.push(svc["version"].as_str().unwrap().to_owned());
        }
        for pkg in setup
            .get("package")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            let v = pkg["version"].as_str().unwrap();
            if v != "none" {
                versions.push(v.to_owned());
            }
        }
    }
    assert!(versions.len() >= 15, "{versions:?}");
    for v in &versions {
        assert!(PlainVersion::parse(v).is_ok(), "fixture version {v:?}");
    }
    // `lab/up.sh`'s plain() also lets `:` and `/` through; a version with
    // either is refused here (a blind spot upstream), never a panic.
    for v in ["1:2.0", "a/b", "1.0 ", "1.0'", "1;2", "$(x)", "1\n"] {
        assert!(PlainVersion::parse(v).is_err(), "{v:?}");
    }
    for v in ["1.0_rc1", "1~rc1", "1!2.0+local-3"] {
        assert!(PlainVersion::parse(v).is_ok(), "{v:?}");
    }
    // The one shared definition of the extra characters.
    assert_eq!(VERSION_PUNCTUATION, ".+~_-");
}

// ------------------------------------------ caps on every outside-text slot

#[test]
fn versions_cannot_look_like_options_or_paths() {
    for bad in [
        ".", "..", "-x", "--help", "-", "+1", "_1", "0!-x", "0!.", "1!~2",
    ] {
        assert!(PlainVersion::parse(bad).is_err(), "{bad:?}");
    }
    for good in ["0", "1.0", "0!1", "v1", "1-x"] {
        assert!(PlainVersion::parse(good).is_ok(), "{good:?}");
    }
}

#[test]
fn outside_text_and_unknown_detail_are_capped_and_checked_on_load() {
    let long = "é".repeat(2000);
    // Built through the constructors, they are cut to the cap with the marker.
    let text = OutsideText::new(&long);
    assert!(text.untrusted().byte_len() <= MAX_OUTSIDE_TEXT_BYTES);
    assert!(text.untrusted().expose_untrusted().ends_with(CUT_MARKER)); // test reads its own value
    let u = Unknown::with_detail(UnknownReason::NoReply, &long);
    assert!(u.detail().unwrap().byte_len() <= MAX_DETAIL_BYTES);
    // Loaded from JSON over the cap: refused. At the cap: accepted.
    let wrap = |n: usize| format!(r#"{{"untrusted":"{}"}}"#, "x".repeat(n));
    assert!(serde_json::from_str::<OutsideText>(&wrap(MAX_OUTSIDE_TEXT_BYTES)).is_ok());
    assert!(serde_json::from_str::<OutsideText>(&wrap(MAX_OUTSIDE_TEXT_BYTES + 1)).is_err());
    let unknown_json = |n: usize| format!(r#"{{"reason":"NoReply","detail":{}}}"#, wrap(n));
    assert!(serde_json::from_str::<Unknown>(&unknown_json(MAX_DETAIL_BYTES)).is_ok());
    assert!(serde_json::from_str::<Unknown>(&unknown_json(MAX_DETAIL_BYTES + 1)).is_err());
    assert!(serde_json::from_str::<Unknown>(r#"{"reason":"NoReply","detail":null}"#).is_ok());
    // A fact whose slots hold oversized text is refused on load too.
    let f = hostile_fact("a");
    let mut doc: Json = serde_json::from_str(&json(&f)).unwrap();
    doc["claim"]["Host"]["os"]["untrusted"] = Json::String("x".repeat(5000));
    assert!(serde_json::from_value::<Fact>(doc).is_err());
}

proptest! {
    #![proptest_config(config())]

    /// Whatever text goes into an outside-text slot, the stored size is capped.
    #[test]
    fn every_outside_text_slot_is_capped(text in proptest::collection::vec(any::<char>(), 0..1500)
        .prop_map(|c| c.into_iter().collect::<String>())) {
        let f = hostile_fact(&text);
        let back: Fact = serde_json::from_str(&json(&f)).unwrap();
        prop_assert_eq!(json(&back), json(&f));
        for claim in hostile_other_claims(&text) {
            let g = fact(Subject::Host, claim);
            let again: Fact = serde_json::from_str(&json(&g)).unwrap();
            prop_assert_eq!(json(&again), json(&g));
        }
    }
}

// ------------------------------------------------------ ASCII-only JSON

proptest! {
    #![proptest_config(config())]

    #[test]
    fn ascii_json_has_no_raw_non_ascii_or_markup_and_means_the_same(text in hostile_text()) {
        let f = hostile_fact(&text);
        let out = to_ascii_json(&f).unwrap();
        prop_assert!(out.bytes().all(|b| (0x20..0x7f).contains(&b)), "{out}");
        prop_assert!(!out.contains(['<', '>', '&']), "{out}");
        // Same meaning: parses to the same value as plain serde_json output.
        let a: Json = serde_json::from_str(&out).unwrap();
        let b: Json = serde_json::from_str(&json(&f)).unwrap();
        prop_assert_eq!(a, b);
    }
}

#[test]
fn ascii_json_escapes_the_named_attacks() {
    let t = Untrusted::new("a\u{9b}31m\u{202e}b\u{2028}</script>\u{1f415}&".to_owned());
    let out = to_ascii_json(&t).unwrap();
    let bs = "\\";
    let expected = [
        "{\"untrusted\":\"a",
        bs,
        "u009b31m",
        bs,
        "u202eb",
        bs,
        "u2028",
        bs,
        "u003c/script",
        bs,
        "u003e",
        bs,
        "ud83d",
        bs,
        "udc15",
        bs,
        "u0026\"}",
    ]
    .concat();
    assert_eq!(out, expected);
    // Plain serde_json leaves them raw, which is why the writer exists.
    assert!(json(&t).contains('\u{9b}'));
}

// ------------------------------------------- the Untrusted wrapper's shape

#[test]
fn duplicate_keys_and_an_empty_object_are_refused() {
    for bad in [
        r#"{"untrusted":"a","untrusted":"b"}"#,
        "{}",
        r#"{"untrusted":"a","x":1}"#,
        r#"{"x":"a"}"#,
    ] {
        assert!(
            serde_json::from_str::<Untrusted<String>>(bad).is_err(),
            "{bad}"
        );
    }
}

// ------------------------------------------------- unidentified instances

fn unrecognized_on(candidates: Vec<CatalogId>) -> Fact {
    fact(
        Subject::Host,
        Claim::Unrecognized {
            candidates,
            runs_as: container("mystery"),
            version_label: None,
            source_label: None,
        },
    )
}

#[test]
fn a_running_product_can_still_have_an_unidentified_second_instance() {
    let lnd = instance("lnd");
    let facts = [
        service_fact("lnd", "0.18.0", Method::ServiceReply),
        unrecognized_on(vec![cat("lnd")]),
    ];
    let v = setup_view(&facts);
    // Running is unchanged, and the view still says something else may be lnd.
    assert!(matches!(
        v.state(&lnd),
        Observed::Seen(ServiceState::Running)
    ));
    assert!(matches!(v.service(&lnd), Observed::Seen(_)));
    assert!(v.may_be_unidentified(&cat("lnd")));
    assert!(!v.may_be_unidentified(&cat("strfry")));
}

#[test]
fn no_service_fact_plus_an_unidentified_endpoint_is_unknown_not_absent() {
    let lnd = instance("lnd");
    let v = setup_view(&[unrecognized_on(vec![cat("lnd")])]);
    assert!(v.may_be_unidentified(&cat("lnd")));
    assert!(is_unknown(&v.state(&lnd), UnknownReason::Unidentified));
    assert!(is_unknown(
        &v.package(&instance("bitcoin-core"), &cat("lnd")),
        UnknownReason::Unidentified
    ));
    // A not-found state names the same reason, not a bare NotChecked.
    let not_found = fact(
        Subject::Service(lnd.clone()),
        Claim::Service {
            state: ServiceState::not_found(Coverage::Complete, witness()),
            version: unknown(UnknownReason::NotChecked),
            runs_as: container("lnd"),
            method: Method::Port,
        },
    );
    let v = setup_view(&[not_found, unrecognized_on(vec![cat("lnd")])]);
    assert!(is_unknown(&v.state(&lnd), UnknownReason::Unidentified));
}

#[test]
fn without_an_unidentified_endpoint_nothing_is_flagged() {
    let v = setup_view(&[service_fact("lnd", "0.18.0", Method::ServiceReply)]);
    assert!(!v.may_be_unidentified(&cat("lnd")));
    assert!(is_unknown(
        &v.state(&instance("strfry")),
        UnknownReason::NotChecked
    ));
    let v = setup_view(&[unrecognized_on(vec![])]);
    assert!(!v.may_be_unidentified(&cat("lnd")));
}

#[test]
fn a_conflict_is_reported_over_not_checked() {
    let id = SettingId::parse("option_enabled").unwrap();
    let setting = |value: Observed<SettingValue>| {
        fact(
            Subject::Service(instance("bitcoin-core")),
            Claim::Setting {
                key: id.clone(),
                value,
            },
        )
    };
    let conflict = || setting(unknown(UnknownReason::Conflict));
    let gap = || setting(unknown(UnknownReason::NotChecked));
    for facts in [[conflict(), gap()], [gap(), conflict()]] {
        assert!(is_unknown(
            &setup_view(&facts).setting(&id),
            UnknownReason::Conflict
        ));
    }
}

#[test]
fn repeated_candidates_collapse_to_one() {
    // Repeats collapse; the same id forty times is one candidate.
    let repeated = unrecognized_on(vec![cat("lnd"); 40]);
    let back: Fact = serde_json::from_str(&json(&repeated)).unwrap();
    assert!(matches!(
        &back.claim,
        Claim::Unrecognized { candidates, .. } if candidates.len() == 1
    ));
}

#[test]
fn wire_structs_refuse_unknown_keys() {
    let f = fact(Subject::Host, Claim::Chain(unknown(UnknownReason::NoReply)));
    let mut top: Json = serde_json::from_str(&json(&f)).unwrap();
    assert!(serde_json::from_value::<Fact>(top.clone()).is_ok());
    top["extra"] = Json::Bool(true);
    assert!(serde_json::from_value::<Fact>(top).is_err());

    let u: Json = serde_json::from_str(&json(&Unknown::new(UnknownReason::NoReply))).unwrap();
    assert!(serde_json::from_value::<Unknown>(u.clone()).is_ok());
    let mut u = u;
    u["extra"] = Json::Bool(true);
    assert!(serde_json::from_value::<Unknown>(u).is_err());

    let e = Evidence::new(CallId::parse("version").unwrap(), "x");
    let mut e: Json = serde_json::from_str(&json(&e)).unwrap();
    e["extra"] = Json::Bool(true);
    assert!(serde_json::from_value::<Evidence>(e).is_err());

    let s = json(&Presence::absent(Coverage::Complete, witness()));
    let mut s: Json = serde_json::from_str(&s).unwrap();
    assert!(serde_json::from_value::<Observed<Presence>>(s.clone()).is_ok());
    s["Seen"]["Absent"]["extra"] = Json::Bool(true);
    assert!(serde_json::from_value::<Observed<Presence>>(s).is_err());
}

// -------------------------------------------- round two: conflicts and caps

fn orders<T: Clone>(a: T, b: T) -> [Vec<T>; 2] {
    [vec![a.clone(), b.clone()], vec![b, a]]
}

fn lnd_state_fact(state: Observed<ServiceState>) -> Fact {
    fact(
        Subject::Service(instance("lnd")),
        Claim::Service {
            state,
            version: unknown(UnknownReason::NotChecked),
            runs_as: container("lnd"),
            method: Method::Port,
        },
    )
}

#[test]
fn a_conflict_is_never_overruled_by_a_seen_value_in_either_order() {
    let lnd = instance("lnd");
    let conflict = || lnd_state_fact(unknown(UnknownReason::Conflict));
    for (seen, name) in [
        (
            ServiceState::not_found(Coverage::Complete, witness()),
            "NotFound",
        ),
        (Observed::Seen(ServiceState::Running), "Running"),
    ] {
        for facts in orders(lnd_state_fact(seen.clone()), conflict()) {
            let v = setup_view(&facts);
            assert!(
                is_unknown(&v.state(&lnd), UnknownReason::Conflict),
                "{name}"
            );
        }
    }
    // Package presence: Absent against Conflict.
    let pkg = |presence| pkg_fact(presence, unknown(UnknownReason::NotChecked));
    for facts in orders(
        pkg(Presence::absent(Coverage::Complete, witness())),
        pkg(unknown(UnknownReason::Conflict)),
    ) {
        let v = setup_view(&facts);
        assert!(is_unknown(
            &v.package(&instance("lnd"), &cat("xz-utils")),
            UnknownReason::Conflict
        ));
    }
    // Package version: Present with a version against Present with a Conflict.
    for facts in orders(
        pkg_fact(
            Observed::Seen(Presence::Present),
            Observed::Seen(version("5.4")),
        ),
        pkg_fact(
            Observed::Seen(Presence::Present),
            unknown(UnknownReason::Conflict),
        ),
    ) {
        let v = setup_view(&facts);
        assert!(matches!(
            v.package(&instance("lnd"), &cat("xz-utils")),
            Observed::Seen(PackageState::Installed(o)) if is_unknown(&o, UnknownReason::Conflict)
        ));
    }
    // A setting and the chain.
    let id = SettingId::parse("option_enabled").unwrap();
    let setting = |value| {
        fact(
            Subject::Setup,
            Claim::Setting {
                key: id.clone(),
                value,
            },
        )
    };
    for facts in orders(
        setting(Observed::Seen(SettingValue::Disabled)),
        setting(unknown(UnknownReason::Conflict)),
    ) {
        assert!(is_unknown(
            &setup_view(&facts).setting(&id),
            UnknownReason::Conflict
        ));
    }
    let chain = |c| fact(Subject::Setup, Claim::Chain(c));
    for facts in orders(
        chain(Observed::Seen(Chain::Main)),
        chain(unknown(UnknownReason::Conflict)),
    ) {
        assert!(is_unknown(
            &setup_view(&facts).chain,
            UnknownReason::Conflict
        ));
    }
}

#[test]
fn an_absence_never_beats_an_unidentified_unknown_but_presence_does() {
    let pkg = |presence| pkg_fact(presence, unknown(UnknownReason::NotChecked));
    let key = (instance("lnd"), cat("xz-utils"));
    for facts in orders(
        pkg(Presence::absent(Coverage::Complete, witness())),
        pkg(unknown(UnknownReason::Unidentified)),
    ) {
        assert!(is_unknown(
            &setup_view(&facts).package(&key.0, &key.1),
            UnknownReason::Unidentified
        ));
    }
    for facts in orders(
        pkg(Observed::Seen(Presence::Present)),
        pkg(unknown(UnknownReason::Unidentified)),
    ) {
        assert!(matches!(
            setup_view(&facts).package(&key.0, &key.1),
            Observed::Seen(PackageState::Installed(_))
        ));
    }
    for facts in orders(
        lnd_state_fact(ServiceState::not_found(Coverage::Complete, witness())),
        lnd_state_fact(unknown(UnknownReason::Unidentified)),
    ) {
        assert!(is_unknown(
            &setup_view(&facts).state(&instance("lnd")),
            UnknownReason::Unidentified
        ));
    }
}

#[test]
fn package_absence_is_also_guarded_by_the_containing_service() {
    let inside = instance("bitcoin-core");
    let absent = fact(
        Subject::Service(inside.clone()),
        Claim::Package {
            product: cat("xz-utils"),
            presence: Presence::absent(Coverage::Complete, witness()),
            version: unknown(UnknownReason::NotChecked),
        },
    );
    let plain = setup_view(std::slice::from_ref(&absent));
    assert!(matches!(
        plain.package(&inside, &cat("xz-utils")),
        Observed::Seen(PackageState::NotInstalled)
    ));
    for facts in orders(absent, unrecognized_on(vec![cat("bitcoin-core")])) {
        let v = setup_view(&facts);
        assert!(is_unknown(
            &v.package(&inside, &cat("xz-utils")),
            UnknownReason::Unidentified
        ));
        // A package nobody mentioned inside it is guarded the same way.
        assert!(is_unknown(
            &v.package(&inside, &cat("zlib")),
            UnknownReason::Unidentified
        ));
    }
}

#[test]
fn a_stopped_instance_stays_stopped_and_the_product_is_still_flagged() {
    let lnd = instance("lnd");
    let v = setup_view(&[
        lnd_state_fact(Observed::Seen(ServiceState::Stopped)),
        unrecognized_on(vec![cat("lnd")]),
    ]);
    assert!(matches!(
        v.state(&lnd),
        Observed::Seen(ServiceState::Stopped)
    ));
    assert!(v.may_be_unidentified(&cat("lnd")));
}

#[test]
fn products_known_only_from_candidates_are_listed() {
    let v = setup_view(&[
        service_fact("lnd", "0.18.0", Method::ServiceReply),
        unrecognized_on(vec![cat("strfry"), cat("lnd"), cat("strfry")]),
    ]);
    let listed: Vec<&str> = v.unidentified().map(|c| c.as_str()).collect();
    assert_eq!(listed, ["lnd", "strfry"]);
    // `services()` does not list a product that only a candidate mentions.
    assert!(v.services().all(|(i, _)| i.catalog != cat("strfry")));
}

#[test]
fn a_fact_that_can_be_built_can_be_read_back_and_a_long_candidate_list_is_refused() {
    let many =
        |n: usize| -> Vec<CatalogId> { (0..n).map(|i| cat(&format!("product-{i}"))).collect() };
    let build = |c: Vec<CatalogId>| {
        Fact::new(
            Subject::Host,
            Claim::Unrecognized {
                candidates: c,
                runs_as: container("mystery"),
                version_label: None,
                source_label: None,
            },
            source(SensorId::Fixture),
            Timestamp(1),
            vec![],
        )
    };
    let ok = build(many(32)).unwrap();
    assert!(serde_json::from_str::<Fact>(&json(&ok)).is_ok());
    assert!(build(many(33)).is_err());
    // 33 copies of one id are one candidate, in the builder and on load.
    let same = build(vec![cat("lnd"); 33]).unwrap();
    assert!(serde_json::from_str::<Fact>(&json(&same)).is_ok());
    let mut doc: Json = serde_json::from_str(&json(&same)).unwrap();
    doc["claim"]["Unrecognized"]["candidates"] = serde_json::json!(vec!["lnd"; 33]);
    assert!(serde_json::from_value::<Fact>(doc.clone()).is_ok());
    doc["claim"]["Unrecognized"]["candidates"] =
        serde_json::json!((0..33).map(|i| format!("product-{i}")).collect::<Vec<_>>());
    assert!(serde_json::from_value::<Fact>(doc).is_err());
}

#[test]
fn claim_source_and_run_shapes_refuse_unknown_keys() {
    let f = fact(
        Subject::Service(instance("lnd")),
        Claim::Service {
            state: Observed::Seen(ServiceState::Running),
            version: Observed::Seen(version("1.0")),
            runs_as: container("lnd"),
            method: Method::Port,
        },
    );
    let good: Json = serde_json::from_str(&json(&f)).unwrap();
    assert!(serde_json::from_value::<Fact>(good.clone()).is_ok());
    for path in [
        "/claim/Service",
        "/claim/Service/runs_as/Container",
        "/source",
        "/subject/Service",
    ] {
        let mut bad = good.clone();
        bad.pointer_mut(path).unwrap()["extra"] = Json::Bool(true);
        assert!(serde_json::from_value::<Fact>(bad).is_err(), "{path}");
    }
}
