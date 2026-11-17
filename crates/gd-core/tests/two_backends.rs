//! Two back ends, views must agree (after Super Testnet's `hedgehog_v3`,
//! which runs one test both offline and on regtest and compares what each
//! side thinks).
//!
//! A judge sees a setup through a back end. The same judge, run on two back
//! ends that describe the same setup, must see the same facts; any difference
//! fails and is printed fact by fact. Three back ends describe the regtest
//! lab today:
//!
//! - `fixture`: the `lab-regtest` setup in `fixtures/expected-matches.toml`,
//!   Judge B's written-down view of the lab.
//! - `lab-recorded`: `fixtures/lab-recorded/manifest.toml`, a manifest a real
//!   `lab/up.sh` run wrote, committed as it came out. Its `# image` lines must
//!   equal the images `lab/compose.yml` pins, so changing an image forces a
//!   re-recording. Compared on every `cargo test`.
//! - `lab-live`: `lab/.data/manifest.toml`, the last manifest `lab/up.sh`
//!   wrote from the running services (`lab/down.sh` deletes it). Compared only
//!   with `GD_LAB=1`, which fails if it is missing; without it the test says
//!   SKIPPED, so the same commit gives the same result.
//!
//! Each back end says which fact families it records. A judge reads some
//! families; one that a back end doesn't record is listed as "not compared",
//! and that list is pinned (`LAB_NOT_COMPARED`), so a gap is never silent.
//! Today the lab manifest records chain, platform, source, arch, block
//! storage, exposure and service versions (`lab/up.sh` reads the last three
//! kinds from `docker inspect` of the running containers); Judge B also reads
//! the packages inside the images, which only the fixture has.
//!
//! The manifest carries text the services reported, so it is read strictly:
//! at most 16 KiB, exact keys, the exact format line, ids from `[a-z0-9-]`,
//! versions from `lab/up.sh`'s `plain()` characters, a printable-ASCII
//! description. Nothing from it reaches an error message unless it is an id.
//!
//! Adding Judge A or Judge C: a row in `JUDGES` naming the families it reads,
//! and each back end filling those families (for the lab, a new allowlisted
//! manifest key written by `lab/up.sh`), or an updated `LAB_NOT_COMPARED`.
//! Judge D reads its corpus, not a setup, so it has no back end to compare.

// Test-only crate: helper functions panic as failed checks. See expected_matches.rs.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::collections::{BTreeMap, BTreeSet};
use std::env::VarError;
use std::fs;
use std::io::{ErrorKind, Read as _, Write as _};
use std::path::{Path, PathBuf};

use toml::{Table, Value};
use yaml_rust2::YamlLoader;

const FIXTURE_FILE: &str = "fixtures/expected-matches.toml";
const FIXTURE_SETUP: &str = "lab-regtest";
const RECORDED_FILE: &str = "fixtures/lab-recorded/manifest.toml";
const LIVE_FILE: &str = "lab/.data/manifest.toml";
const COMPOSE_FILE: &str = "lab/compose.yml";
const UP_SH: &str = "lab/up.sh";

const MANIFEST_KEYS: [&str; 10] = [
    "arch",
    "block_storage",
    "chain",
    "description",
    "exposure",
    "format",
    "platform",
    "recorder",
    "service",
    "source",
];
const MANIFEST_SERVICE_KEYS: [&str; 2] = ["id", "version"];
const MANIFEST_RECORDER: &str = "lab/up.sh format 1";
const MAX_SERVICES: usize = 32;
/// A real manifest is about 2 KB; anything over this is refused unread.
const MAX_MANIFEST_BYTES: usize = 16 * 1024;
const MAX_DESCRIPTION: usize = 200;

/// What a back end says about a setup: the families of facts it records, and
/// the facts themselves as sorted `key -> value` pairs. A key's family is its
/// first word: `chain`, `platform`, `service lnd`, `package lnd xz-utils`.
#[derive(Debug, Clone, PartialEq, Eq)]
struct View {
    records: &'static [&'static str],
    facts: BTreeMap<String, String>,
}

/// The fact families each back end records.
const FIXTURE_RECORDS: &[&str] = &[
    "arch",
    "block_storage",
    "chain",
    "exposure",
    "package",
    "platform",
    "service",
    "source",
];
const MANIFEST_RECORDS: &[&str] = &[
    "arch",
    "block_storage",
    "chain",
    "exposure",
    "platform",
    "service",
    "source",
];
/// The one-word facts a manifest records, each `[a-z0-9-]`.
const MANIFEST_WORDS: [&str; 6] = [
    "arch",
    "block_storage",
    "chain",
    "exposure",
    "platform",
    "source",
];

/// One judge: its name and the fact families it reads. Judge B's matcher
/// reads the products and versions, the packages inside them, the chain, and
/// the platform facts that scope an advisory (`expected_matches.rs`).
struct Judge {
    name: &'static str,
    reads: &'static [&'static str],
}

/// Every judge that reads a setup. Judge A and Judge C add a row here, and
/// each back end records the families they read (or the gap is listed).
const JUDGES: &[Judge] = &[Judge {
    name: "Judge B",
    reads: &[
        "arch",
        "block_storage",
        "chain",
        "exposure",
        "package",
        "platform",
        "service",
    ],
}];

/// What comparing two back ends found.
#[derive(Debug, Default, PartialEq, Eq)]
struct Comparison {
    /// Facts both back ends record and give differently, sorted, in plain words.
    disagreements: Vec<String>,
    /// Families a judge reads that one back end doesn't record, so they were
    /// not compared. Never silent: the tests pin this list.
    not_compared: Vec<String>,
    /// How many facts were actually compared, over every judge.
    compared: usize,
}

fn family(key: &str) -> &str {
    key.split(' ').next().unwrap_or(key)
}

fn root() -> PathBuf {
    PathBuf::from(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(rel: &str) -> String {
    fs::read_to_string(root().join(rel)).unwrap_or_else(|e| panic!("cannot read {rel}: {e}"))
}

/// Read at most `MAX_MANIFEST_BYTES` + 1 bytes, so an oversized file is never
/// loaded whole. `NotFound` is `Ok(None)`; every other error, and a symlink
/// or folder, is an error (never a skip). The file is opened first and then
/// checked, so nothing can slip in between a look and the open.
fn read_manifest_file(path: &Path) -> Result<Option<String>, String> {
    let rel = path.display();
    let file = match fs::File::open(path) {
        Err(e) if e.kind() == ErrorKind::NotFound => return Ok(None),
        Err(e) => return Err(format!("cannot open {rel}: {e}")),
        Ok(f) => f,
    };
    // `file.metadata()` is of the opened file (a folder opens fine on Unix);
    // `symlink_metadata` is of the path, which is how a symlink shows.
    let opened_is_file = file
        .metadata()
        .map_err(|e| format!("cannot look at {rel}: {e}"))?
        .is_file();
    let path_is_file = fs::symlink_metadata(path)
        .map_err(|e| format!("cannot look at {rel}: {e}"))?
        .file_type()
        .is_file();
    if !opened_is_file || !path_is_file {
        return Err(format!("{rel} is not a plain file (a symlink or a folder)"));
    }
    let mut bytes = Vec::new();
    file.take(MAX_MANIFEST_BYTES as u64 + 1)
        .read_to_end(&mut bytes)
        .map_err(|e| format!("cannot read {rel}: {e}"))?;
    String::from_utf8(bytes)
        .map(Some)
        .map_err(|_| format!("{rel} is not UTF-8"))
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
    let mut facts = BTreeMap::new();
    let mut put = |key: String, value: &str| {
        assert!(
            facts.insert(key.clone(), value.to_owned()).is_none(),
            "{setup}: {key} listed twice"
        );
    };
    for key in [
        "arch",
        "block_storage",
        "chain",
        "exposure",
        "platform",
        "source",
    ] {
        put(
            key.to_owned(),
            s[key].as_str().expect("setup field is text"),
        );
    }
    for svc in s["service"].as_array().expect("[[setup.service]]") {
        let id = svc["id"].as_str().expect("service id");
        put(
            format!("service {id}"),
            svc["version"].as_str().expect("service version"),
        );
    }
    for pkg in s
        .get("package")
        .and_then(Value::as_array)
        .into_iter()
        .flatten()
    {
        let (inside, product) = (
            pkg["in"].as_str().unwrap(),
            pkg["product"].as_str().unwrap(),
        );
        put(
            format!("package {inside} {product}"),
            pkg["version"].as_str().expect("package version"),
        );
    }
    View {
        records: FIXTURE_RECORDS,
        facts,
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
/// Strict, because its versions are text the services reported. Nothing from
/// the file reaches an error message unless it passed `is_id`.
fn parse_manifest(text: &str) -> Result<View, String> {
    if text.len() > MAX_MANIFEST_BYTES {
        return Err(format!("over {MAX_MANIFEST_BYTES} bytes"));
    }
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
    let mut facts = BTreeMap::new();
    for key in MANIFEST_WORDS {
        let value = field(key)?;
        if !is_id(value) {
            return Err(format!(
                "{key} has characters outside [a-z0-9-] or the wrong length"
            ));
        }
        facts.insert(key.to_owned(), value.to_owned());
    }
    if facts["source"] != "lab" {
        return Err("source is not lab".to_owned());
    }
    let description = field("description")?;
    if description.is_empty()
        || description.len() > MAX_DESCRIPTION
        || !description
            .bytes()
            .all(|b| b == b' ' || b.is_ascii_graphic())
    {
        return Err(format!(
            "description is not 1 to {MAX_DESCRIPTION} printable ASCII characters"
        ));
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
        facts.insert(format!("service {id}"), version.to_owned());
    }
    Ok(View {
        records: MANIFEST_RECORDS,
        facts,
    })
}

/// Compare two back ends for every judge. Within a family both record, a fact
/// one side lacks is a disagreement. A family one side doesn't record goes in
/// `not_compared`, by name, never silently.
fn compare(a_name: &str, a: &View, b_name: &str, b: &View) -> Comparison {
    let mut out = Comparison::default();
    for judge in JUDGES {
        let mut both = Vec::new();
        for fam in judge.reads {
            let missing: Vec<&str> = [(a_name, a), (b_name, b)]
                .iter()
                .filter(|(_, v)| !v.records.contains(fam))
                .map(|(n, _)| *n)
                .collect();
            if missing.is_empty() {
                both.push(*fam);
            } else {
                out.not_compared.push(format!(
                    "{}: {fam} (not recorded by {})",
                    judge.name,
                    missing.join(" or ")
                ));
            }
        }
        let keys: BTreeSet<&String> = a
            .facts
            .keys()
            .chain(b.facts.keys())
            .filter(|k| both.contains(&family(k)))
            .collect();
        out.compared += keys.len();
        for key in keys {
            let j = judge.name;
            match (a.facts.get(key), b.facts.get(key)) {
                (Some(x), Some(y)) if x == y => {}
                (Some(x), Some(y)) => out
                    .disagreements
                    .push(format!("{j}: {key}: {a_name} says {x}, {b_name} says {y}")),
                (Some(x), None) => out.disagreements.push(format!(
                    "{j}: {key}: {a_name} says {x}, {b_name} has nothing"
                )),
                (None, Some(y)) => out.disagreements.push(format!(
                    "{j}: {key}: {a_name} has nothing, {b_name} says {y}"
                )),
                (None, None) => {}
            }
        }
    }
    out
}

/// What the lab manifest can't show Judge B yet, pinned so that recording
/// more (or a judge reading more) has to update it on purpose.
const LAB_NOT_COMPARED: [&str; 1] = ["Judge B: package (not recorded by {lab})"];

/// Assert the fixture and a lab back end agree, and that exactly the known
/// gaps were left out. Returns how many facts were actually compared.
fn assert_agree(fixture: &View, lab_name: &str, lab: &View) -> usize {
    let c = compare("fixture", fixture, lab_name, lab);
    assert!(
        c.disagreements.is_empty(),
        "the fixture and {lab_name} back ends disagree on {} fact(s):\n  {}",
        c.disagreements.len(),
        c.disagreements.join("\n  ")
    );
    let expected: Vec<String> = LAB_NOT_COMPARED
        .iter()
        .map(|s| s.replace("{lab}", lab_name))
        .collect();
    assert_eq!(c.not_compared, expected, "the families left out changed");
    c.compared
}

/// The `org.guard-dog.lab.id` label of each service in `lab/compose.yml`, with
/// its pinned image.
fn compose_images() -> BTreeMap<String, String> {
    let docs = YamlLoader::load_from_str(&read(COMPOSE_FILE)).unwrap();
    let mut out = BTreeMap::new();
    for svc in docs[0]["services"].as_hash().unwrap().values() {
        let id = svc["labels"]["org.guard-dog.lab.id"].as_str().unwrap();
        let image = svc["image"].as_str().unwrap();
        assert!(
            out.insert(id.to_owned(), image.to_owned()).is_none(),
            "two services in {COMPOSE_FILE} share the id {id}"
        );
    }
    out
}

/// The `# image <ref>` comment `lab/up.sh` writes above each `[[service]]`,
/// paired with the id that follows it. Errors never echo the line: it may
/// hold anything. An image line with no id after it (a dangling last line) is
/// an error too.
fn manifest_images(text: &str) -> Result<BTreeMap<String, String>, String> {
    let mut out = BTreeMap::new();
    let mut image: Option<(usize, &str)> = None;
    for (n, line) in text.lines().enumerate() {
        let n = n + 1;
        if let Some(rest) = line.strip_prefix("# image ") {
            if image.replace((n, rest)).is_some() {
                return Err(format!("line {n}: a second # image line before an id"));
            }
        } else if let Some(rest) = line.strip_prefix("id = \"") {
            let id = rest
                .strip_suffix('"')
                .filter(|id| is_id(id))
                .ok_or_else(|| format!("line {n}: an id line not in up.sh's shape"))?;
            let (_, img) = image
                .take()
                .ok_or_else(|| format!("line {n}: no # image line above service {id}"))?;
            if out.insert(id.to_owned(), img.to_owned()).is_some() {
                return Err(format!("line {n}: service {id} listed twice"));
            }
        }
    }
    if let Some((n, _)) = image {
        return Err(format!("line {n}: a # image line with no service after it"));
    }
    Ok(out)
}

/// The `# <name> reported "<text>" (<how>)` comment `lab/up.sh` writes above
/// each `[[service]]`: what the service itself said, paired with the id that
/// follows. The text must be `plain()` characters. Errors never echo a line.
fn manifest_reported(text: &str) -> Result<BTreeMap<String, String>, String> {
    let mut out = BTreeMap::new();
    let mut pending: Option<(usize, &str)> = None;
    for (n, line) in text.lines().enumerate() {
        let n = n + 1;
        if let Some((name, rest)) = line
            .strip_prefix("# ")
            .and_then(|l| l.split_once(" reported \""))
        {
            let reported = rest
                .split_once("\" (")
                .map(|(r, _)| r)
                .filter(|r| is_id(name) && is_plain(r))
                .ok_or_else(|| format!("line {n}: a reported line not in up.sh's shape"))?;
            if pending.replace((n, reported)).is_some() {
                return Err(format!("line {n}: a second reported line before an id"));
            }
        } else if let Some(rest) = line.strip_prefix("id = \"") {
            let id = rest
                .strip_suffix('"')
                .filter(|id| is_id(id))
                .ok_or_else(|| format!("line {n}: an id line not in up.sh's shape"))?;
            if let Some((_, reported)) = pending.take() {
                out.insert(id.to_owned(), reported.to_owned());
            }
        }
    }
    if let Some((n, _)) = pending {
        return Err(format!(
            "line {n}: a reported line with no service after it"
        ));
    }
    Ok(out)
}

/// The version `lab/up.sh` derives from a service's reported text, by the
/// same rules (`# 9.` in `lab/up.sh`): Bitcoin Core's `/Satoshi:32.1.0/` is
/// `32.1`, Core Lightning drops a leading `v`, Nutshell drops `Nutshell/`,
/// LND and strfry are used as they are. `None` for an id with no rule.
fn version_from_reported(id: &str, reported: &str) -> Option<String> {
    match id {
        "bitcoin-core" => {
            let v = reported.strip_prefix("/Satoshi:")?.strip_suffix('/')?;
            let parts: Vec<&str> = v.split('.').collect();
            match parts.as_slice() {
                [a, b, "0"] => Some(format!("{a}.{b}")),
                [_, _, _] => Some(v.to_owned()),
                _ => None,
            }
        }
        "core-lightning" => Some(reported.strip_prefix('v').unwrap_or(reported).to_owned()),
        "nutshell" => reported.strip_prefix("Nutshell/").map(str::to_owned),
        "lnd" | "strfry" => Some(reported.to_owned()),
        _ => None,
    }
}

/// Every service in `view` has a reported text in `text`, and the text and the
/// version agree.
fn check_reported(text: &str, view: &View) -> Result<(), String> {
    let reported = manifest_reported(text)?;
    for (key, version) in &view.facts {
        let Some(id) = key.strip_prefix("service ") else {
            continue;
        };
        let said = reported
            .get(id)
            .ok_or_else(|| format!("service {id}: no reported text above it"))?;
        let derived = version_from_reported(id, said).ok_or_else(|| {
            format!("service {id}: reported text {said} is not in its usual shape")
        })?;
        if &derived != version {
            return Err(format!(
                "service {id}: reported {said} means version {derived}, but the manifest says {version}"
            ));
        }
    }
    Ok(())
}

/// The images a manifest names must be exactly the ones `lab/compose.yml`
/// pins, one per service.
fn assert_images_match(text: &str, what: &str) {
    let images = manifest_images(text).unwrap_or_else(|e| panic!("{what}: {e}"));
    assert!(
        images == compose_images(),
        "{what} was not recorded from the images {COMPOSE_FILE} pins; re-record it (lab/README.md)"
    );
}

/// `GD_LAB`: unset, empty or `0` means no lab is expected; `1` means one is up
/// and must be compared. Anything else is a mistake, not a quiet skip.
fn lab_expected() -> bool {
    match std::env::var("GD_LAB").as_deref() {
        Err(VarError::NotPresent) | Ok("" | "0") => false,
        Ok("1") => true,
        Ok(_) | Err(VarError::NotUnicode(_)) => panic!("GD_LAB must be unset, 0 or 1"),
    }
}

/// Written straight to stderr, so it shows in a plain `cargo test` run too
/// (libtest hides `eprintln!` from passing tests).
fn notice(text: &str) {
    let _ = writeln!(std::io::stderr(), "{text}");
}

fn view(records: &'static [&'static str], facts: &[(&str, &str)]) -> View {
    View {
        records,
        facts: facts
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
chain = "regtest"
arch = "64-bit"
block_storage = "tmpfs"
exposure = "none"
description = "Guard Dog regtest lab."

# bitcoind reported "/Satoshi:32.1.0/" (bitcoin-cli getnetworkinfo .subversion)
# image bitcoin/bitcoin@sha256:00
[[service]]
id = "bitcoin-core"
version = "32.1"

# lnd reported "0.21.6-beta" (lncli version .lnd.version)
# image lightninglabs/lnd@sha256:11
[[service]]
id = "lnd"
version = "0.21.6-beta"
"#;

#[test]
fn the_recorded_lab_agrees_with_the_fixtures() {
    let fixture = fixture_view(&read(FIXTURE_FILE), FIXTURE_SETUP);
    let text = read_manifest_file(&root().join(RECORDED_FILE))
        .unwrap_or_else(|e| panic!("{e}"))
        .unwrap_or_else(|| panic!("{RECORDED_FILE} is missing"));
    let recorded =
        parse_manifest(&text).unwrap_or_else(|e| panic!("{RECORDED_FILE} is refused: {e}"));
    assert_eq!(
        fixture.facts["chain"], "regtest",
        "{FIXTURE_SETUP} is a regtest setup"
    );
    // The recording is of today's lab: every pinned service, each under the
    // image `lab/compose.yml` pins now. Re-record after changing an image.
    assert_images_match(&text, RECORDED_FILE);
    check_reported(&text, &recorded).unwrap_or_else(|e| panic!("{RECORDED_FILE}: {e}"));
    let compared = assert_agree(&fixture, "lab-recorded", &recorded);
    assert_eq!(
        compared,
        5 + compose_images().len(),
        "chain, platform, arch, block storage, exposure and every service"
    );
}

#[test]
fn the_live_lab_agrees_with_the_fixtures() {
    if !lab_expected() {
        notice(
            "SKIPPED the_live_lab_agrees_with_the_fixtures: set GD_LAB=1 while a lab is up (lab/up.sh)",
        );
        return;
    }
    let text = read_manifest_file(&root().join(LIVE_FILE))
        .unwrap_or_else(|e| panic!("{e}"))
        .unwrap_or_else(|| {
            panic!("GD_LAB=1 but {LIVE_FILE} is missing: start the lab with lab/up.sh first")
        });
    let live = parse_manifest(&text).unwrap_or_else(|e| panic!("{LIVE_FILE} is refused: {e}"));
    assert_images_match(&text, LIVE_FILE);
    check_reported(&text, &live).unwrap_or_else(|e| panic!("{LIVE_FILE}: {e}"));
    let fixture = fixture_view(&read(FIXTURE_FILE), FIXTURE_SETUP);
    let compared = assert_agree(&fixture, "lab-live", &live);
    notice(&format!(
        "two back ends: the fixture and the last lab/up.sh manifest agree on {compared} fact(s) for {} judge(s); not compared: {}",
        JUDGES.len(),
        LAB_NOT_COMPARED.len()
    ));
}

#[test]
fn disagreements_are_named_field_by_field() {
    let all = FIXTURE_RECORDS;
    let base = view(
        all,
        &[
            ("chain", "regtest"),
            ("service bitcoin-core", "32.1"),
            ("service lnd", "0.21.6-beta"),
        ],
    );
    let same = compare("fixture", &base, "lab", &base.clone());
    assert!(same.disagreements.is_empty() && same.not_compared.is_empty());
    assert_eq!(same.compared, 3);

    let cases: [(&str, View, &[&str]); 6] = [
        (
            "a version differs",
            view(
                all,
                &[
                    ("chain", "regtest"),
                    ("service bitcoin-core", "32.0"),
                    ("service lnd", "0.21.6-beta"),
                ],
            ),
            &["Judge B: service bitcoin-core: fixture says 32.1, lab says 32.0"],
        ),
        (
            "a service is missing",
            view(
                all,
                &[("chain", "regtest"), ("service bitcoin-core", "32.1")],
            ),
            &["Judge B: service lnd: fixture says 0.21.6-beta, lab has nothing"],
        ),
        (
            "an extra service",
            view(
                all,
                &[
                    ("chain", "regtest"),
                    ("service bitcoin-core", "32.1"),
                    ("service lnd", "0.21.6-beta"),
                    ("service strfry", "1.1.2"),
                ],
            ),
            &["Judge B: service strfry: fixture has nothing, lab says 1.1.2"],
        ),
        (
            "the chain differs",
            view(
                all,
                &[
                    ("chain", "signet"),
                    ("service bitcoin-core", "32.1"),
                    ("service lnd", "0.21.6-beta"),
                ],
            ),
            &["Judge B: chain: fixture says regtest, lab says signet"],
        ),
        (
            "a package only one side has (both record packages)",
            view(
                all,
                &[
                    ("chain", "regtest"),
                    ("package lnd xz-utils", "5.6.0"),
                    ("service bitcoin-core", "32.1"),
                    ("service lnd", "0.21.6-beta"),
                ],
            ),
            &["Judge B: package lnd xz-utils: fixture has nothing, lab says 5.6.0"],
        ),
        (
            "two facts differ, reported in sorted order",
            view(
                all,
                &[
                    ("chain", "regtest"),
                    ("service bitcoin-core", "32.1.0"),
                    ("service lnd", "v0.21.6-beta"),
                ],
            ),
            &[
                "Judge B: service bitcoin-core: fixture says 32.1, lab says 32.1.0",
                "Judge B: service lnd: fixture says 0.21.6-beta, lab says v0.21.6-beta",
            ],
        ),
    ];
    for (what, other, expected) in cases {
        let c = compare("fixture", &base, "lab", &other);
        assert_eq!(
            c.disagreements,
            expected.iter().map(|s| (*s).to_owned()).collect::<Vec<_>>(),
            "{what}"
        );
        assert!(c.not_compared.is_empty(), "{what}");
    }

    // A family one side doesn't record is listed, never silently passed.
    let lab = view(
        MANIFEST_RECORDS,
        &[
            ("chain", "regtest"),
            ("service bitcoin-core", "32.1"),
            ("service lnd", "0.21.6-beta"),
        ],
    );
    let with_package = view(
        all,
        &[
            ("chain", "regtest"),
            ("package lnd xz-utils", "5.6.0"),
            ("service bitcoin-core", "32.1"),
            ("service lnd", "0.21.6-beta"),
        ],
    );
    let c = compare("fixture", &with_package, "lab", &lab);
    assert!(c.disagreements.is_empty());
    assert_eq!(
        c.not_compared,
        LAB_NOT_COMPARED
            .iter()
            .map(|s| s.replace("{lab}", "lab"))
            .collect::<Vec<_>>()
    );
}

#[test]
fn a_good_manifest_is_read_exactly() {
    assert_eq!(
        parse_manifest(GOOD_MANIFEST),
        Ok(view(
            MANIFEST_RECORDS,
            &[
                ("arch", "64-bit"),
                ("block_storage", "tmpfs"),
                ("chain", "regtest"),
                ("exposure", "none"),
                ("platform", "docker"),
                ("service bitcoin-core", "32.1"),
                ("service lnd", "0.21.6-beta"),
                ("source", "lab"),
            ]
        ))
    );
    assert_eq!(
        manifest_images(GOOD_MANIFEST),
        Ok(BTreeMap::from([
            (
                "bitcoin-core".to_owned(),
                "bitcoin/bitcoin@sha256:00".to_owned()
            ),
            ("lnd".to_owned(), "lightninglabs/lnd@sha256:11".to_owned()),
        ]))
    );
    // Broken image lines are refused without echoing the line.
    let bidi = GOOD_MANIFEST
        .replace("# image lightninglabs/lnd@sha256:11\n", "")
        .replace("id = \"lnd\"", "id = \"lnd\" # \u{202e}evil");
    for (what, text, reason) in [
        (
            "a second image line",
            GOOD_MANIFEST.replace("# image lightninglabs", "# image x\n# image lightninglabs"),
            "line 20: a second # image line before an id",
        ),
        (
            "no image line",
            GOOD_MANIFEST.replace("# image lightninglabs/lnd@sha256:11\n", ""),
            "line 20: no # image line above service lnd",
        ),
        (
            "an id line with a trailing comment holding a bidi override",
            bidi,
            "line 20: an id line not in up.sh's shape",
        ),
    ] {
        let err = manifest_images(&text).unwrap_err();
        assert_eq!(err, reason, "{what}");
        assert!(err.is_ascii(), "{what}");
    }
}

#[test]
fn an_oversized_or_odd_file_is_never_read_whole() {
    let dir = PathBuf::from(env!("CARGO_TARGET_TMPDIR")).join("two-backends");
    fs::create_dir_all(&dir).unwrap();
    let big = dir.join("big.toml");
    fs::write(&big, "#".repeat(MAX_MANIFEST_BYTES * 4)).unwrap();
    let text = read_manifest_file(&big).unwrap().unwrap();
    assert_eq!(
        text.len(),
        MAX_MANIFEST_BYTES + 1,
        "only one byte past the limit is read"
    );
    assert_eq!(
        parse_manifest(&text).map(|_| ()),
        Err(format!("over {MAX_MANIFEST_BYTES} bytes"))
    );
    assert_eq!(read_manifest_file(&dir.join("none.toml")), Ok(None));
    assert!(
        read_manifest_file(&dir)
            .unwrap_err()
            .contains("not a plain file")
    );
    #[cfg(unix)]
    {
        let link = dir.join("link.toml");
        let _ = fs::remove_file(&link);
        std::os::unix::fs::symlink(root().join(RECORDED_FILE), &link).unwrap();
        assert!(
            read_manifest_file(&link)
                .unwrap_err()
                .contains("not a plain file"),
            "a symlink is refused, even to a good manifest"
        );
    }
}

#[test]
fn every_broken_manifest_is_refused() {
    let lnd = "[[service]]\nid = \"lnd\"\nversion = \"0.21.6-beta\"\n";
    let cases: [(&str, String, &str); 31] = [
        ("not TOML", "format = = 1".to_owned(), "not valid TOML"),
        (
            "an unknown top-level key",
            format!("network = \"regtest\"\n{GOOD_MANIFEST}"),
            "unknown key \"network\"",
        ),
        (
            "no chain",
            GOOD_MANIFEST.replace("chain = \"regtest\"\n", ""),
            "missing chain",
        ),
        (
            "a chain with odd characters",
            GOOD_MANIFEST.replace("chain = \"regtest\"", "chain = \"reg test\""),
            "chain has characters outside [a-z0-9-] or the wrong length",
        ),
        (
            "a bidi override in the description",
            GOOD_MANIFEST.replace("regtest lab.", "regtest \\u202elab."),
            "description is not 1 to 200 printable ASCII characters",
        ),
        (
            "a description over 200 characters",
            GOOD_MANIFEST.replace("regtest lab.", &"x".repeat(201)),
            "description is not 1 to 200 printable ASCII characters",
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
            "a source with odd characters",
            GOOD_MANIFEST.replace("source = \"lab\"", "source = \"Lab Recording\""),
            "source has characters outside [a-z0-9-] or the wrong length",
        ),
        (
            "a recording, not the lab",
            GOOD_MANIFEST.replace("source = \"lab\"", "source = \"recording\""),
            "source is not lab",
        ),
        (
            "no arch",
            GOOD_MANIFEST.replace("arch = \"64-bit\"\n", ""),
            "missing arch",
        ),
        (
            "no block storage",
            GOOD_MANIFEST.replace("block_storage = \"tmpfs\"\n", ""),
            "missing block_storage",
        ),
        (
            "no exposure",
            GOOD_MANIFEST.replace("exposure = \"none\"\n", ""),
            "missing exposure",
        ),
        (
            "an arch with odd characters",
            GOOD_MANIFEST.replace("arch = \"64-bit\"", "arch = \"64 bit\""),
            "arch has characters outside [a-z0-9-] or the wrong length",
        ),
        (
            "an exposure as a number",
            GOOD_MANIFEST.replace("exposure = \"none\"", "exposure = 0"),
            "exposure is not text",
        ),
        (
            "no description",
            GOOD_MANIFEST.replace("description = \"Guard Dog regtest lab.\"\n", ""),
            "missing description",
        ),
        (
            "a control character in the description",
            GOOD_MANIFEST.replace("regtest lab.", "regtest lab.\\u001b[2J"),
            "description is not 1 to 200 printable ASCII characters",
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
        r#"printf 'chain = "%s"\n' "$BTC_CHAIN""#,
        r#"printf 'format = 1\nplatform = "docker"\nsource = "lab"\nrecorder = "lab/up.sh format 1"\n'"#,
        r#"[[service]]\nid = "%s"\nversion = "%s"\n"#,
        r#"> "$DATA/manifest.toml""#,
    ] {
        assert!(up.contains(line), "lab/up.sh no longer writes: {line}");
    }
    for svc in [
        "BTC_CHAIN",
        "BTC_RAW",
        "LND_RAW",
        "CLN_RAW",
        "STRFRY_RAW",
        "NUT_RAW",
    ] {
        assert!(
            up.contains(&format!("{svc}=\"$(plain ")),
            "lab/up.sh still checks {svc}, text a service reported, with plain()"
        );
    }
    let gitignore = read(".gitignore");
    assert!(
        gitignore
            .lines()
            .any(|l| l.trim() == "lab/.data/" || l.trim() == "/lab/.data/"),
        "lab/.data/ (the live manifest and the lab's credentials) stays ignored"
    );
}

#[test]
fn up_sh_writes_the_container_facts() {
    let up = read(UP_SH);
    for line in [
        r#"printf 'arch = "%s"\nblock_storage = "%s"\nexposure = "%s"\n' "$LAB_ARCH" "$LAB_STORAGE" "$LAB_EXPOSURE""#,
        "docker image inspect -f '{{.Architecture}}'",
        "{{.HostConfig.ReadonlyRootfs}}",
        "{{range .Mounts}}{{.Type}} {{end}}",
        ".PortBindings",
    ] {
        assert!(up.contains(line), "lab/up.sh no longer has: {line}");
    }
}

#[test]
fn reported_text_and_version_must_agree() {
    let good = parse_manifest(GOOD_MANIFEST).unwrap();
    // GOOD_MANIFEST has a reported line for bitcoind (above bitcoin-core) and lnd.
    assert_eq!(check_reported(GOOD_MANIFEST, &good), Ok(()));
    assert_eq!(
        manifest_reported(GOOD_MANIFEST),
        Ok(BTreeMap::from([
            ("bitcoin-core".to_owned(), "/Satoshi:32.1.0/".to_owned()),
            ("lnd".to_owned(), "0.21.6-beta".to_owned()),
        ]))
    );
    for (what, text, reason) in [
        (
            "a Satoshi string that says another version",
            GOOD_MANIFEST.replace("/Satoshi:32.1.0/", "/Satoshi:32.2.0/"),
            "service bitcoin-core: reported /Satoshi:32.2.0/ means version 32.2, but the manifest says 32.1",
        ),
        (
            "a reported text that is not Satoshi-shaped",
            GOOD_MANIFEST.replace("/Satoshi:32.1.0/", "32.1.0"),
            "service bitcoin-core: reported text 32.1.0 is not in its usual shape",
        ),
        (
            "an lnd that says another version",
            GOOD_MANIFEST.replace(
                "lnd reported \"0.21.6-beta\"",
                "lnd reported \"0.21.5-beta\"",
            ),
            "service lnd: reported 0.21.5-beta means version 0.21.5-beta, but the manifest says 0.21.6-beta",
        ),
        (
            "no reported text for a service",
            GOOD_MANIFEST.replace(
                "# lnd reported \"0.21.6-beta\" (lncli version .lnd.version)\n",
                "",
            ),
            "service lnd: no reported text above it",
        ),
        (
            "a reported text with an escape in it",
            GOOD_MANIFEST.replace("0.21.6-beta\" (lncli", "0.21.6\u{1b}[2J\" (lncli"),
            "line 18: a reported line not in up.sh's shape",
        ),
        (
            "two reported lines before one id",
            GOOD_MANIFEST.replace("# lnd reported", "# x reported \"1\" (y)\n# lnd reported"),
            "line 19: a second reported line before an id",
        ),
    ] {
        let err = check_reported(&text, &good).unwrap_err();
        assert_eq!(err, reason, "{what}");
        assert!(err.is_ascii() && !err.contains('\u{1b}'), "{what}");
    }
    // The rules match `lab/up.sh` step 9 for every service the lab runs.
    for (id, said, version) in [
        ("bitcoin-core", "/Satoshi:32.1.0/", "32.1"),
        ("bitcoin-core", "/Satoshi:32.1.1/", "32.1.1"),
        ("core-lightning", "v26.06.9", "26.06.9"),
        ("lnd", "0.21.6-beta", "0.21.6-beta"),
        ("nutshell", "Nutshell/0.21.0", "0.21.0"),
        ("strfry", "1.1.2-148-g4cd3cf6", "1.1.2-148-g4cd3cf6"),
    ] {
        assert_eq!(version_from_reported(id, said).as_deref(), Some(version));
    }
    assert_eq!(version_from_reported("mystery", "1"), None);
}

#[test]
fn a_dangling_last_line_is_refused() {
    for tail in ["# image x@sha256:22\n", "# image x@sha256:22"] {
        let text = format!("{GOOD_MANIFEST}{tail}");
        assert_eq!(
            manifest_images(&text),
            Err("line 23: a # image line with no service after it".to_owned())
        );
    }
    let text = format!("{GOOD_MANIFEST}# x reported \"1\" (y)\n");
    assert_eq!(
        manifest_reported(&text),
        Err("line 23: a reported line with no service after it".to_owned())
    );
    assert_eq!(manifest_images(GOOD_MANIFEST).map(|m| m.len()), Ok(2));
}

/// A small fixed-seed generator (splitmix64), so the property tests below
/// draw the same cases on every machine.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        self.0 = self.0.wrapping_add(0x9E37_79B9_7F4A_7C15);
        let mut z = self.0;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58_476D_1CE4_E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D0_49BB_1331_11EB);
        z ^ (z >> 31)
    }
    fn below(&mut self, n: usize) -> usize {
        usize::try_from(self.next() % n as u64).unwrap()
    }
    fn pick<'a>(&mut self, items: &[&'a str]) -> &'a str {
        items[self.below(items.len())]
    }
    fn string(&mut self, alphabet: &[u8], min: usize, max: usize) -> String {
        let len = min + self.below(max - min + 1);
        (0..len)
            .map(|_| char::from(alphabet[self.below(alphabet.len())]))
            .collect()
    }
}

const WORD_ALPHABET: &[u8] = b"abcdefghijklmnopqrstuvwxyz0123456789";
const VERSION_ALPHABET: &[u8] = b"0123456789.-+_:abcdef";
const KNOWN_IDS: [&str; 5] = [
    "bitcoin-core",
    "core-lightning",
    "lnd",
    "nutshell",
    "strfry",
];

/// A random well-formed manifest in `lab/up.sh`'s shape, with the view and
/// the images and reported texts it should read back as.
struct Generated {
    text: String,
    view: View,
    images: BTreeMap<String, String>,
    reported: BTreeMap<String, String>,
}

fn word(rng: &mut Rng) -> String {
    let mut w = rng.string(WORD_ALPHABET, 1, 12);
    if rng.below(3) == 0 {
        w.push('-');
        w.push_str(&rng.string(WORD_ALPHABET, 1, 6));
    }
    w
}

fn generate_manifest(rng: &mut Rng) -> Generated {
    let mut words = BTreeMap::new();
    for key in MANIFEST_WORDS {
        let value = if key == "source" {
            "lab".to_owned()
        } else {
            word(rng)
        };
        words.insert(key, value);
    }
    // Sorted, unique ids: a random subset of the known ones plus random others.
    let mut ids = BTreeSet::new();
    for id in KNOWN_IDS {
        if rng.below(2) == 0 {
            ids.insert(id.to_owned());
        }
    }
    for _ in 0..rng.below(6) {
        ids.insert(format!("x{}", word(rng)));
    }
    if ids.is_empty() {
        ids.insert("lnd".to_owned());
    }
    let mut text = String::from("# Written by lab/up.sh.\nformat = 1\n");
    text.push_str("recorder = \"lab/up.sh format 1\"\n");
    for key in MANIFEST_WORDS {
        text.push_str(&format!("{key} = \"{}\"\n", words[key]));
    }
    text.push_str("description = \"Random lab.\"\n");
    let mut facts: BTreeMap<String, String> = words
        .iter()
        .map(|(k, v)| ((*k).to_owned(), v.clone()))
        .collect();
    let (mut images, mut reported) = (BTreeMap::new(), BTreeMap::new());
    for id in ids {
        let version = format!("{}.{}.{}", rng.below(100), rng.below(100), 1 + rng.below(9));
        let version = if id.starts_with('x') {
            rng.string(VERSION_ALPHABET, 1, 64)
        } else {
            version
        };
        let image = format!("img/{id}@sha256:{}", rng.string(b"0123456789abcdef", 8, 8));
        text.push('\n');
        if let Some(said) = match id.as_str() {
            "bitcoin-core" => Some(format!("/Satoshi:{version}/")),
            "core-lightning" => Some(format!("v{version}")),
            "nutshell" => Some(format!("Nutshell/{version}")),
            "lnd" | "strfry" => Some(version.clone()),
            _ => None,
        } {
            text.push_str(&format!("# {id} reported \"{said}\" (some call)\n"));
            reported.insert(id.clone(), said);
        }
        text.push_str(&format!("# image {image}\n[[service]]\nid = \"{id}\"\n"));
        text.push_str(&format!("version = \"{version}\"\n"));
        facts.insert(format!("service {id}"), version);
        images.insert(id, image);
    }
    Generated {
        text,
        view: View {
            records: MANIFEST_RECORDS,
            facts,
        },
        images,
        reported,
    }
}

const SEED: u64 = 0x6764_5f74_776f_6265;

#[test]
fn random_well_formed_manifests_round_trip() {
    let mut rng = Rng(SEED);
    for case in 0..300 {
        let g = generate_manifest(&mut rng);
        assert_eq!(
            parse_manifest(&g.text).as_ref(),
            Ok(&g.view),
            "case {case}:\n{}",
            g.text
        );
        assert_eq!(manifest_images(&g.text), Ok(g.images), "case {case}");
        assert_eq!(manifest_reported(&g.text), Ok(g.reported), "case {case}");
        // Where the rules know the service, the reported text agrees by construction.
        let known = View {
            records: MANIFEST_RECORDS,
            facts: g
                .view
                .facts
                .iter()
                .filter(|(k, _)| {
                    k.strip_prefix("service ")
                        .is_some_and(|id| KNOWN_IDS.contains(&id))
                })
                .map(|(k, v)| (k.clone(), v.clone()))
                .collect(),
        };
        assert_eq!(check_reported(&g.text, &known), Ok(()), "case {case}");
    }
}

/// Lines with a key from `MANIFEST_WORDS` etc. removed, one at a time.
fn without_line(text: &str, prefix: &str) -> String {
    text.lines()
        .filter(|l| !l.starts_with(prefix))
        .map(|l| format!("{l}\n"))
        .collect()
}

#[test]
fn random_malformed_manifests_are_refused_by_name_and_never_panic() {
    let mut rng = Rng(SEED ^ 0xFFFF);
    let bad_chars = [" ", "!", "$", "*", "(", "A", "é"];
    for case in 0..300 {
        let g = generate_manifest(&mut rng);
        let any_id = g.images.keys().next().unwrap().clone();
        let (what, text, reason): (&str, String, String) = match rng.below(6) {
            0 => {
                let key = rng.pick(&[
                    "recorder",
                    "chain",
                    "platform",
                    "source",
                    "arch",
                    "block_storage",
                    "exposure",
                    "description",
                ]);
                (
                    "a required line deleted",
                    without_line(&g.text, &format!("{key} = ")),
                    format!("missing {key}"),
                )
            }
            1 => {
                let junk = format!("zz{}", rng.string(WORD_ALPHABET, 1, 8));
                (
                    "an unknown key",
                    g.text
                        .replacen("description", &format!("{junk} = 1\ndescription"), 1),
                    format!("unknown key {junk:?}"),
                )
            }
            2 => {
                let key = rng.pick(&MANIFEST_WORDS);
                let bad = format!("a{}", rng.pick(&bad_chars));
                let old = format!("{key} = \"{}\"", g.view.facts[key]);
                (
                    "a bad word",
                    g.text.replacen(&old, &format!("{key} = \"{bad}\""), 1),
                    format!("{key} has characters outside [a-z0-9-] or the wrong length"),
                )
            }
            3 => {
                let old = format!(
                    "version = \"{}\"",
                    g.view.facts[&format!("service {any_id}")]
                );
                let bad = format!("1{}", rng.pick(&bad_chars[..5]));
                (
                    "a bad version",
                    g.text.replacen(&old, &format!("version = \"{bad}\""), 1),
                    format!(
                        "service {any_id}: version has characters outside [0-9A-Za-z.+_:/-] or the wrong length"
                    ),
                )
            }
            4 => {
                let block = format!("[[service]]\nid = \"{any_id}\"\nversion = \"1\"\n");
                (
                    "a service listed twice",
                    format!("{}\n{block}", g.text),
                    format!("service {any_id}: services are not sorted by id, or listed twice"),
                )
            }
            _ => {
                let mut line = format!("zz{}", rng.string(b"[]=\"'\\.,{}#a-z0-9 \t", 0, 12));
                line.push('\n');
                (
                    "a line of junk at the end",
                    format!("{}{line}", g.text),
                    String::new(),
                )
            }
        };
        let err = parse_manifest(&text)
            .map(|_| ())
            .expect_err(&format!("case {case}: {what} was accepted:\n{text}"));
        assert!(
            err.is_ascii() && !err.is_empty() && !err.chars().any(char::is_control),
            "case {case}: {what}: the error is not plain text"
        );
        if !reason.is_empty() {
            assert_eq!(err, reason, "case {case}: {what}");
        }
    }
}

#[test]
fn random_bytes_and_cut_manifests_never_panic() {
    let mut rng = Rng(SEED ^ 0xABCD);
    for case in 0..500 {
        // Pure noise, including quotes, brackets, escapes and non-ASCII.
        let len = rng.below(400);
        let noise: String = (0..len)
            .map(|_| match rng.below(4) {
                0 => char::from(u8::try_from(rng.below(128)).unwrap()),
                1 => char::from_u32(0x80 + u32::try_from(rng.below(0x700)).unwrap()).unwrap(),
                _ => char::from(b"[]=\"'\\.,{}#\n abc019-"[rng.below(20)]),
            })
            .collect();
        let err = parse_manifest(&noise)
            .map(|_| ())
            .expect_err(&format!("case {case}: noise was accepted"));
        assert!(
            err.is_ascii() && !err.is_empty() && !err.chars().any(char::is_control),
            "case {case}: the error is not plain text"
        );
        let _ = manifest_images(&noise);
        let _ = manifest_reported(&noise);

        // A good manifest cut at a random place: Ok or a plain named error.
        let g = generate_manifest(&mut rng);
        let mut cut = rng.below(g.text.len() + 1);
        while !g.text.is_char_boundary(cut) {
            cut -= 1;
        }
        if let Err(e) = parse_manifest(&g.text[..cut]) {
            assert!(
                e.is_ascii() && !e.is_empty() && !e.chars().any(char::is_control),
                "case {case}: the error is not plain text"
            );
        }
        let _ = manifest_images(&g.text[..cut]);
        let _ = manifest_reported(&g.text[..cut]);
    }
}
