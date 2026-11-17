//! Two back ends, views must agree (after Super Testnet's `hedgehog_v3`,
//! which runs one test both offline and on regtest and compares what each
//! side thinks).
//!
//! A judge sees a setup through a back end. The same judge, run on two back
//! ends that describe the same setup, must see the same thing; any difference
//! fails and is printed field by field. Three back ends describe the regtest
//! lab today:
//!
//! - `fixture`: the `lab-regtest` setup in `fixtures/expected-matches.toml`,
//!   Judge B's written-down view of the lab.
//! - `lab-recorded`: `fixtures/lab-recorded/manifest.toml`, a manifest a real
//!   `lab/up.sh` run wrote, committed as it came out. Re-record it when a lab
//!   image changes. Compared on every `cargo test`.
//! - `lab-live`: `lab/.data/manifest.toml`, which `lab/up.sh` writes from the
//!   running services and `lab/down.sh` deletes. Compared only while a lab is
//!   up; otherwise the test prints SKIPPED and passes, unless
//!   `GD_LAB_REQUIRED=1` is set, when a missing lab fails.
//!
//! The manifest carries text the services reported, so it is read strictly:
//! exact keys, the exact format line, and ids and versions from a small
//! character set (the same one `lab/up.sh`'s `plain()` enforces).
//!
//! Judges plug in through `JUDGES`: each projects a setup to the fields it
//! reads. Judge B reads service ids and versions. Judge A (inventory) and
//! Judge C (egress) add a row when they land. Judge D reads its corpus, not a
//! setup, so it has no back end to compare.

// Test-only crate: helper functions panic as failed checks. See expected_matches.rs.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::collections::BTreeMap;
use std::fs;
use std::path::PathBuf;

use toml::{Table, Value};

const FIXTURE_FILE: &str = "fixtures/expected-matches.toml";
const FIXTURE_SETUP: &str = "lab-regtest";
const RECORDED_FILE: &str = "fixtures/lab-recorded/manifest.toml";
const LIVE_FILE: &str = "lab/.data/manifest.toml";
const UP_SH: &str = "lab/up.sh";
/// The lab only ever runs on regtest: `lab/up.sh` removes itself otherwise.
const LAB_CHAIN: &str = "regtest";

const MANIFEST_KEYS: [&str; 6] = [
    "description",
    "format",
    "platform",
    "recorder",
    "service",
    "source",
];
const MANIFEST_SERVICE_KEYS: [&str; 2] = ["id", "version"];
const MANIFEST_RECORDER: &str = "lab/up.sh format 1";
const MAX_SERVICES: usize = 32;

/// What a back end says about a setup.
#[derive(Debug, Clone, PartialEq, Eq)]
struct View {
    chain: String,
    /// Service id to version, sorted.
    services: BTreeMap<String, String>,
}

/// One judge: its name and the fields of a view it reads, as sorted
/// `field -> value` pairs. Two back ends agree for a judge when these are equal.
type Projection = fn(&View) -> BTreeMap<String, String>;

/// Judge B matches advisories against the setup's products and versions on
/// its chain.
fn judge_b(view: &View) -> BTreeMap<String, String> {
    let mut fields = BTreeMap::new();
    fields.insert("chain".to_owned(), view.chain.clone());
    for (id, version) in &view.services {
        fields.insert(format!("service {id}"), version.clone());
    }
    fields
}

/// Every judge that reads a setup. Judge A and Judge C add a row here.
const JUDGES: [(&str, Projection); 1] = [("Judge B", judge_b)];

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(rel: &str) -> String {
    fs::read_to_string(root().join(rel)).unwrap_or_else(|e| panic!("cannot read {rel}: {e}"))
}

/// The `fixture` back end: the named setup in expected-matches.toml.
fn fixture_view(text: &str, setup: &str) -> View {
    let doc: Table = toml::from_str(text).expect("expected-matches.toml is TOML");
    let setups = doc["setup"].as_array().expect("[[setup]] list");
    let found: Vec<&Table> = setups
        .iter()
        .filter_map(Value::as_table)
        .filter(|t| t.get("id").and_then(Value::as_str) == Some(setup))
        .collect();
    assert_eq!(
        found.len(),
        1,
        "exactly one setup {setup:?} in {FIXTURE_FILE}"
    );
    let s = found[0];
    let mut services = BTreeMap::new();
    for svc in s["service"].as_array().expect("[[setup.service]]") {
        let id = svc["id"].as_str().expect("service id").to_owned();
        let version = svc["version"].as_str().expect("service version").to_owned();
        assert!(
            services.insert(id.clone(), version).is_none(),
            "{setup}: service {id} listed twice"
        );
    }
    View {
        chain: s["chain"].as_str().expect("setup chain").to_owned(),
        services,
    }
}

/// `[a-z0-9-]`, 1 to 40 characters, starting and ending with a letter or digit.
fn is_id(s: &str) -> bool {
    (1..=40).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_lowercase() || b.is_ascii_digit() || b == b'-')
        && !s.starts_with('-')
        && !s.ends_with('-')
}

/// `lab/up.sh`'s `plain()`: `^[0-9A-Za-z.+_:/-]{1,64}$`.
fn is_plain(s: &str) -> bool {
    (1..=64).contains(&s.len())
        && s.bytes()
            .all(|b| b.is_ascii_alphanumeric() || b".+_:/-".contains(&b))
}

/// An error naming a key from the manifest, but only if the key is plain:
/// anything else in it is text we never print.
fn named(what: &str, key: &str) -> String {
    if is_id(key) {
        format!("{what} {key:?}")
    } else {
        format!("{what} with unusual characters")
    }
}

/// The `lab-recorded` and `lab-live` back ends: a manifest `lab/up.sh` wrote.
/// Strict, because its versions are text the services reported.
fn parse_manifest(text: &str) -> Result<View, String> {
    let doc: Table = toml::from_str(text).map_err(|_| "not valid TOML".to_owned())?;
    for key in doc.keys() {
        if !MANIFEST_KEYS.contains(&key.as_str()) {
            return Err(named("unknown key", key));
        }
    }
    let field = |key: &str| -> Result<&str, String> {
        doc.get(key)
            .ok_or_else(|| format!("missing {key}"))?
            .as_str()
            .ok_or_else(|| format!("{key} is not text"))
    };
    if doc.get("format").and_then(Value::as_integer) != Some(1) {
        return Err("format is not 1".to_owned());
    }
    if field("recorder")? != MANIFEST_RECORDER {
        return Err("recorder is not lab/up.sh format 1".to_owned());
    }
    if field("source")? != "lab" {
        return Err("source is not lab".to_owned());
    }
    if field("platform")? != "docker" {
        return Err("platform is not docker".to_owned());
    }
    let description = field("description")?;
    if description.is_empty() || description.chars().any(char::is_control) {
        return Err("description is empty or has a control character".to_owned());
    }
    let list = doc
        .get("service")
        .ok_or("missing [[service]]")?
        .as_array()
        .ok_or("service is not a [[service]] list")?;
    if list.is_empty() || list.len() > MAX_SERVICES {
        return Err(format!(
            "{} services, expected 1 to {MAX_SERVICES}",
            list.len()
        ));
    }
    let mut services = BTreeMap::new();
    let mut previous: Option<String> = None;
    for item in list {
        let svc = item.as_table().ok_or("a service is not a table")?;
        for key in svc.keys() {
            if !MANIFEST_SERVICE_KEYS.contains(&key.as_str()) {
                return Err(named("unknown service key", key));
            }
        }
        let id = svc
            .get("id")
            .and_then(Value::as_str)
            .ok_or("a service has no text id")?;
        let version = svc
            .get("version")
            .and_then(Value::as_str)
            .ok_or("a service has no text version")?;
        if !is_id(id) {
            return Err(
                "a service id has characters outside [a-z0-9-] or the wrong length".to_owned(),
            );
        }
        if !is_plain(version) {
            return Err(format!(
                "service {id}: version has characters outside [0-9A-Za-z.+_:/-] or the wrong length"
            ));
        }
        if previous.as_deref().is_some_and(|p| p >= id) {
            return Err(format!(
                "service {id}: services are not sorted by id, or listed twice"
            ));
        }
        previous = Some(id.to_owned());
        services.insert(id.to_owned(), version.to_owned());
    }
    Ok(View {
        chain: LAB_CHAIN.to_owned(),
        services,
    })
}

/// Every field where two back ends disagree, for every judge, sorted, in
/// plain words. Empty means they agree.
fn disagreements(a_name: &str, a: &View, b_name: &str, b: &View) -> Vec<String> {
    let mut out = Vec::new();
    for (judge, project) in JUDGES {
        let (fa, fb) = (project(a), project(b));
        let mut fields: Vec<&String> = fa.keys().chain(fb.keys()).collect();
        fields.sort();
        fields.dedup();
        for field in fields {
            match (fa.get(field), fb.get(field)) {
                (Some(x), Some(y)) if x == y => {}
                (Some(x), Some(y)) => out.push(format!(
                    "{judge}: {field}: {a_name} says {x}, {b_name} says {y}"
                )),
                (Some(x), None) => out.push(format!(
                    "{judge}: {field}: {a_name} says {x}, {b_name} has nothing"
                )),
                (None, Some(y)) => out.push(format!(
                    "{judge}: {field}: {a_name} has nothing, {b_name} says {y}"
                )),
                (None, None) => {}
            }
        }
    }
    out
}

fn assert_agree(a_name: &str, a: &View, b_name: &str, b: &View) {
    let diff = disagreements(a_name, a, b_name, b);
    assert!(
        diff.is_empty(),
        "the {a_name} and {b_name} back ends disagree on {} field(s):\n  {}",
        diff.len(),
        diff.join("\n  ")
    );
}

fn view(chain: &str, services: &[(&str, &str)]) -> View {
    View {
        chain: chain.to_owned(),
        services: services
            .iter()
            .map(|(k, v)| ((*k).to_owned(), (*v).to_owned()))
            .collect(),
    }
}

/// A manifest in exactly the shape `lab/up.sh` writes.
const GOOD_MANIFEST: &str = r#"# Written by lab/up.sh.
format = 1
platform = "docker"
source = "lab"
recorder = "lab/up.sh format 1"
description = "Guard Dog regtest lab."

# bitcoind reported "/Satoshi:32.1.0/" (bitcoin-cli getnetworkinfo .subversion)
[[service]]
id = "bitcoin-core"
version = "32.1"

[[service]]
id = "lnd"
version = "0.21.6-beta"
"#;

#[test]
fn the_recorded_lab_agrees_with_the_fixtures() {
    let fixture = fixture_view(&read(FIXTURE_FILE), FIXTURE_SETUP);
    let recorded = parse_manifest(&read(RECORDED_FILE))
        .unwrap_or_else(|e| panic!("{RECORDED_FILE} is refused: {e}"));
    assert_eq!(
        fixture.chain, LAB_CHAIN,
        "{FIXTURE_SETUP} is a regtest setup"
    );
    assert_eq!(fixture.services.len(), 5, "the lab runs five services");
    assert_agree("fixture", &fixture, "lab-recorded", &recorded);
}

#[test]
fn the_live_lab_agrees_with_the_fixtures() {
    let required = std::env::var("GD_LAB_REQUIRED").is_ok_and(|v| v == "1");
    let path = root().join(LIVE_FILE);
    if !path.exists() {
        assert!(
            !required,
            "GD_LAB_REQUIRED=1 but {LIVE_FILE} is missing: start the lab with lab/up.sh first"
        );
        eprintln!(
            "SKIPPED the_live_lab_agrees_with_the_fixtures: no lab is up ({LIVE_FILE} is missing)"
        );
        return;
    }
    let fixture = fixture_view(&read(FIXTURE_FILE), FIXTURE_SETUP);
    let live =
        parse_manifest(&read(LIVE_FILE)).unwrap_or_else(|e| panic!("{LIVE_FILE} is refused: {e}"));
    assert_agree("fixture", &fixture, "lab-live", &live);
    eprintln!(
        "two back ends: fixture and lab-live agree on {} service(s) for {} judge(s)",
        live.services.len(),
        JUDGES.len()
    );
}

#[test]
fn disagreements_are_named_field_by_field() {
    let base = view(
        "regtest",
        &[("bitcoin-core", "32.1"), ("lnd", "0.21.6-beta")],
    );
    assert!(disagreements("fixture", &base, "lab", &base.clone()).is_empty());

    let cases: [(&str, View, &[&str]); 5] = [
        (
            "a version differs",
            view(
                "regtest",
                &[("bitcoin-core", "32.0"), ("lnd", "0.21.6-beta")],
            ),
            &["Judge B: service bitcoin-core: fixture says 32.1, lab says 32.0"],
        ),
        (
            "a service is missing",
            view("regtest", &[("bitcoin-core", "32.1")]),
            &["Judge B: service lnd: fixture says 0.21.6-beta, lab has nothing"],
        ),
        (
            "an extra service",
            view(
                "regtest",
                &[
                    ("bitcoin-core", "32.1"),
                    ("lnd", "0.21.6-beta"),
                    ("strfry", "1.1.2"),
                ],
            ),
            &["Judge B: service strfry: fixture has nothing, lab says 1.1.2"],
        ),
        (
            "the chain differs",
            view(
                "signet",
                &[("bitcoin-core", "32.1"), ("lnd", "0.21.6-beta")],
            ),
            &["Judge B: chain: fixture says regtest, lab says signet"],
        ),
        (
            "two fields differ, reported in sorted order",
            view(
                "regtest",
                &[("bitcoin-core", "32.1.0"), ("lnd", "v0.21.6-beta")],
            ),
            &[
                "Judge B: service bitcoin-core: fixture says 32.1, lab says 32.1.0",
                "Judge B: service lnd: fixture says 0.21.6-beta, lab says v0.21.6-beta",
            ],
        ),
    ];
    for (what, other, expected) in cases {
        assert_eq!(
            disagreements("fixture", &base, "lab", &other),
            expected.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>(),
            "{what}"
        );
    }
}

#[test]
fn a_good_manifest_is_read_exactly() {
    assert_eq!(
        parse_manifest(GOOD_MANIFEST),
        Ok(view(
            "regtest",
            &[("bitcoin-core", "32.1"), ("lnd", "0.21.6-beta")]
        ))
    );
}

#[test]
fn every_broken_manifest_is_refused() {
    let lnd = "[[service]]\nid = \"lnd\"\nversion = \"0.21.6-beta\"\n";
    let cases: [(&str, String, &str); 22] = [
        ("not TOML", "format = = 1".to_owned(), "not valid TOML"),
        (
            "an unknown top-level key",
            format!("chain = \"regtest\"\n{GOOD_MANIFEST}"),
            "unknown key \"chain\"",
        ),
        (
            "format 2",
            GOOD_MANIFEST.replace("format = 1", "format = 2"),
            "format is not 1",
        ),
        (
            "format as text",
            GOOD_MANIFEST.replace("format = 1", "format = \"1\""),
            "format is not 1",
        ),
        (
            "another recorder",
            GOOD_MANIFEST.replace("lab/up.sh format 1", "tools/record-setup.sh"),
            "recorder is not lab/up.sh format 1",
        ),
        (
            "a recording, not the lab",
            GOOD_MANIFEST.replace("source = \"lab\"", "source = \"recording\""),
            "source is not lab",
        ),
        (
            "another platform",
            GOOD_MANIFEST.replace("platform = \"docker\"", "platform = \"umbrel\""),
            "platform is not docker",
        ),
        (
            "no description",
            GOOD_MANIFEST.replace("description = \"Guard Dog regtest lab.\"\n", ""),
            "missing description",
        ),
        (
            "a control character in the description",
            GOOD_MANIFEST.replace("regtest lab.", "regtest lab.\\u001b[2J"),
            "description is empty or has a control character",
        ),
        (
            "no services",
            GOOD_MANIFEST
                .split("\n# bitcoind")
                .next()
                .unwrap()
                .to_owned(),
            "missing [[service]]",
        ),
        (
            "an unknown key with a terminal escape",
            format!("\"a\\u001b[2J\" = 1\n{GOOD_MANIFEST}"),
            "unknown key with unusual characters",
        ),
        (
            "an unknown service key",
            GOOD_MANIFEST.replace("version = \"32.1\"", "version = \"32.1\"\nport = 8332"),
            "unknown service key \"port\"",
        ),
        (
            "a service with no version",
            GOOD_MANIFEST.replace("version = \"32.1\"\n", ""),
            "a service has no text version",
        ),
        (
            "a version as a number",
            GOOD_MANIFEST.replace("version = \"32.1\"", "version = 32.1"),
            "a service has no text version",
        ),
        (
            "an upper-case id",
            GOOD_MANIFEST.replace("id = \"lnd\"", "id = \"LND\""),
            "a service id has characters outside [a-z0-9-] or the wrong length",
        ),
        (
            "an id with a path in it",
            GOOD_MANIFEST.replace("id = \"lnd\"", "id = \"../lnd\""),
            "a service id has characters outside [a-z0-9-] or the wrong length",
        ),
        (
            "a version with a space",
            GOOD_MANIFEST.replace("0.21.6-beta", "0.21.6 beta"),
            "service lnd: version has characters outside [0-9A-Za-z.+_:/-] or the wrong length",
        ),
        (
            "a version with a terminal escape",
            GOOD_MANIFEST.replace("0.21.6-beta", "0.21.6\\u001b[31m"),
            "service lnd: version has characters outside [0-9A-Za-z.+_:/-] or the wrong length",
        ),
        (
            "a version with a newline",
            GOOD_MANIFEST.replace("0.21.6-beta", "0.21.6\\nfake = 1"),
            "service lnd: version has characters outside [0-9A-Za-z.+_:/-] or the wrong length",
        ),
        (
            "a version over 64 characters",
            GOOD_MANIFEST.replace("0.21.6-beta", &"9".repeat(65)),
            "service lnd: version has characters outside [0-9A-Za-z.+_:/-] or the wrong length",
        ),
        (
            "a service listed twice",
            format!("{GOOD_MANIFEST}\n{lnd}"),
            "service lnd: services are not sorted by id, or listed twice",
        ),
        (
            "services out of order",
            GOOD_MANIFEST
                .replace("id = \"bitcoin-core\"", "id = \"x\"")
                .replace("id = \"lnd\"", "id = \"bitcoin-core\""),
            "service bitcoin-core: services are not sorted by id, or listed twice",
        ),
    ];
    for (what, text, reason) in &cases {
        assert_eq!(
            parse_manifest(text).as_ref().map(|_| ()),
            Err(&(*reason).to_owned()),
            "{what}"
        );
    }
    let too_many: String = (0..=MAX_SERVICES)
        .map(|i| format!("[[service]]\nid = \"s{i:03}\"\nversion = \"1\"\n"))
        .collect();
    let text = GOOD_MANIFEST
        .split("\n# bitcoind")
        .next()
        .unwrap()
        .to_owned()
        + "\n"
        + &too_many;
    assert_eq!(
        parse_manifest(&text).as_ref().map(|_| ()),
        Err(&format!("33 services, expected 1 to {MAX_SERVICES}"))
    );
}

#[test]
fn up_sh_still_writes_this_format() {
    let up = read(UP_SH);
    for line in [
        r#"printf 'format = 1\nplatform = "docker"\nsource = "lab"\nrecorder = "lab/up.sh format 1"\n'"#,
        r#"[[service]]\nid = "%s"\nversion = "%s"\n"#,
        r#"> "$DATA/manifest.toml""#,
    ] {
        assert!(up.contains(line), "lab/up.sh no longer writes: {line}");
    }
    assert!(
        up.contains("BTC_RAW=\"$(plain ") && up.contains("NUT_RAW=\"$(plain "),
        "lab/up.sh still checks reported text with plain()"
    );
    let gitignore = read(".gitignore");
    assert!(
        gitignore
            .lines()
            .any(|l| l.trim() == "lab/.data/" || l.trim() == "/lab/.data/"),
        "lab/.data/ (the live manifest and the lab's credentials) stays ignored"
    );
}
