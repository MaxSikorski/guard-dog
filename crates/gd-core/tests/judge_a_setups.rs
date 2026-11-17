//! Judge A: recorded real setups.
//!
//! Loads every recorded setup in `fixtures/setups/` (and, on a maintainer's
//! machine, the private ones in `fixtures/private-setups/`), checks the
//! recording format, scores an inventory against the setup's `manifest.toml`,
//! and runs a leak lint (a second, independent detector for secret shapes)
//! over every recorded file. No network, no clock, no randomness: folders and
//! files are visited in sorted order.
//!
//! The inventory is a stub today, so the baseline is 0% by design; Phase 1
//! replaces the stub with the real sensors. The scorer and the lint are proven
//! on synthetic data in `tests/synthetic/`, which never counts in the baseline.

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

use regex::Regex;
use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

const PLATFORMS: [(&str, &str); 7] = [
    ("raspiblitz", "RaspiBlitz"),
    ("umbrel", "Umbrel"),
    ("startos", "StartOS"),
    ("mynode", "myNode"),
    ("nix-bitcoin", "nix-bitcoin"),
    ("docker", "Plain Docker or Compose"),
    ("systemd", "Plain Linux with systemd"),
];

/// The committed recordings, in order. Changes together with `BASELINE`.
const EXPECTED_SETUPS: [&str; 0] = [];

/// Per setup: services, found, versions known, versions right, extra.
#[allow(clippy::type_complexity)]
const BASELINE: [(&str, usize, usize, usize, usize, usize); 0] = [];

const SOURCES: [&str; 4] = ["lab", "maintainer", "tester", "synthetic"];
const CALLS: [&str; 6] = [
    "getnetworkinfo",
    "getinfo",
    "getversion",
    "nip11",
    "nut06",
    "server-version",
];
const PLATFORM_DEFAULTS: [&str; 26] = [
    "admin",
    "bitcoin",
    "lnd",
    "btcpay",
    "electrs",
    "fulcrum",
    "rtl",
    "thunderhub",
    "mempool",
    "tor",
    "debian-tor",
    "lndg",
    "joinmarket",
    "umbrel",
    "start9",
    "mynode",
    "pi",
    "ubuntu",
    "debian",
    "root",
    "raspiblitz",
    "raspberrypi",
    "localhost",
    "nixos",
    "operator",
    "user",
];

fn repo(rel: &str) -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("../../")
        .join(rel)
}

fn slug_ok(s: &str) -> bool {
    Regex::new(r"^[a-z0-9]+(-[a-z0-9]+)*$").unwrap().is_match(s)
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

/// The closed list of file paths a recording may hold (design 2.2).
fn allowed_path(rel: &str) -> bool {
    const FIXED: [&str; 14] = [
        "manifest.toml",
        "record-log.txt",
        "systemctl-list-units.txt",
        "dpkg-query.txt",
        "ss-tlnp.txt",
        "ss-ulnp.txt",
        "torrc",
        "binaries-version.txt",
        "raspiblitz-version.txt",
        "raspiblitz-conf.txt",
        "raspiblitz-info.txt",
        "docker-version.json",
        "docker-ps.json",
        "docker-images.json",
    ];
    if FIXED.contains(&rel) {
        return true;
    }
    let parts: Vec<&str> = rel.split('/').collect();
    match parts.as_slice() {
        ["apps", id, "umbrel-app.yml"] => slug_ok(id) && id.len() <= 40,
        ["apps", id, file] => {
            slug_ok(id)
                && id.len() <= 40
                && Regex::new(r"^[a-z0-9_-]{1,40}\.json$")
                    .unwrap()
                    .is_match(file)
        }
        ["replies", id, file] => {
            slug_ok(id)
                && id.len() <= 40
                && file
                    .strip_suffix(".json")
                    .is_some_and(|call| CALLS.contains(&call))
        }
        _ => false,
    }
}

#[derive(Clone, Debug)]
struct Service {
    id: String,
    version: String,
}

#[derive(Clone, Debug)]
struct Setup {
    platform: String,
    source: String,
    services: Vec<Service>,
}

fn string_key(t: &toml::Table, key: &str) -> Result<String, String> {
    match t.get(key) {
        Some(toml::Value::String(s)) => Ok(s.clone()),
        Some(_) => Err(format!("key `{key}` must be a string")),
        None => Err(format!("missing key `{key}`")),
    }
}

fn only_keys(t: &toml::Table, allowed: &[&str], what: &str) -> Result<(), String> {
    for k in t.keys() {
        if !allowed.contains(&k.as_str()) {
            return Err(format!("unknown key `{k}` in {what}"));
        }
    }
    Ok(())
}

fn collect_files(base: &Path, dir: &Path, acc: &mut Vec<String>) {
    let mut entries: Vec<PathBuf> = fs::read_dir(dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .collect();
    entries.sort();
    for p in entries {
        if p.is_dir() {
            collect_files(base, &p, acc);
        } else {
            acc.push(
                p.strip_prefix(base)
                    .unwrap()
                    .to_string_lossy()
                    .replace('\\', "/"),
            );
        }
    }
}

fn load_setup(dir: &Path) -> Result<Setup, String> {
    let raw = fs::read_to_string(dir.join("manifest.toml"))
        .map_err(|e| format!("manifest.toml cannot be read: {e}"))?;
    let t: toml::Table = raw
        .parse()
        .map_err(|e| format!("manifest.toml is not valid TOML: {e}"))?;
    only_keys(
        &t,
        &[
            "format",
            "platform",
            "source",
            "recorded",
            "recorder",
            "reviewed_by",
            "description",
            "service",
        ],
        "the manifest",
    )?;
    match t.get("format") {
        Some(toml::Value::Integer(1)) => {}
        _ => return Err("format must be the number 1".into()),
    }
    let platform = string_key(&t, "platform")?;
    if !PLATFORMS.iter().any(|(p, _)| *p == platform) {
        return Err(format!(
            "platform `{platform}` is not one of the known platforms"
        ));
    }
    let source = string_key(&t, "source")?;
    if !SOURCES.contains(&source.as_str()) {
        return Err(format!("source `{source}` is not one of {SOURCES:?}"));
    }
    let recorded = string_key(&t, "recorded")?;
    if !is_calendar_date(&recorded) {
        return Err(format!("recorded `{recorded}` is not a real calendar date"));
    }
    if string_key(&t, "recorder")? != "record-setup.sh format 2" {
        return Err("recorder must be `record-setup.sh format 2`".into());
    }
    for key in ["reviewed_by", "description"] {
        if string_key(&t, key)?.trim().is_empty() {
            return Err(format!("{key} must not be empty"));
        }
    }
    let Some(toml::Value::Array(list)) = t.get("service") else {
        return Err("at least one [[service]] is required".into());
    };
    if list.is_empty() {
        return Err("at least one [[service]] is required".into());
    }
    let mut services = Vec::new();
    let mut seen = BTreeSet::new();
    for entry in list {
        let toml::Value::Table(s) = entry else {
            return Err("each [[service]] must be a table".into());
        };
        only_keys(s, &["id", "version", "evidence"], "a [[service]]")?;
        let id = string_key(s, "id")?;
        if !slug_ok(&id) {
            return Err(format!("service id `{id}` is not a lower-case slug"));
        }
        if !seen.insert(id.clone()) {
            return Err(format!("duplicate service id `{id}`"));
        }
        let version = string_key(s, "version")?;
        if version.trim().is_empty() || version.starts_with(['v', 'V']) {
            return Err(format!(
                "service {id}: version `{version}` must be non-empty and not start with v"
            ));
        }
        let Some(toml::Value::Array(evidence)) = s.get("evidence") else {
            return Err(format!("service {id}: evidence must be a list"));
        };
        if evidence.is_empty() {
            return Err(format!("service {id}: evidence must not be empty"));
        }
        for e in evidence {
            let toml::Value::String(path) = e else {
                return Err(format!("service {id}: evidence entries must be strings"));
            };
            if path.starts_with('/') || path.split('/').any(|c| c == ".." || c.is_empty()) {
                return Err(format!(
                    "service {id}: evidence path `{path}` is not a clean relative path"
                ));
            }
            if !dir.join(path).is_file() {
                return Err(format!(
                    "service {id}: evidence file `{path}` does not exist"
                ));
            }
            if !allowed_path(path) {
                return Err(format!(
                    "service {id}: evidence `{path}` is not a recording file"
                ));
            }
        }
        services.push(Service { id, version });
    }
    let log = fs::read_to_string(dir.join("record-log.txt"))
        .map_err(|_| "record-log.txt is missing".to_string())?;
    if log.lines().next() != Some("record-setup.sh format 2") {
        return Err("record-log.txt must start with `record-setup.sh format 2`".into());
    }
    if log.lines().nth(1).is_some_and(|l| l.contains("test-tools")) {
        return Err("test-tools recording: made with the recorder's test tools, not valid".into());
    }
    let mut files = Vec::new();
    collect_files(dir, dir, &mut files);
    for f in files {
        if !allowed_path(&f) {
            return Err(format!("{f} is not a recording file"));
        }
    }
    Ok(Setup {
        platform,
        source,
        services,
    })
}

/// Committed recordings are never synthetic.
fn check_fixture_source(setup: &Setup) -> Result<(), String> {
    if setup.source == "synthetic" {
        return Err("a synthetic setup must not be in fixtures/setups".into());
    }
    Ok(())
}

struct Observed {
    id: String,
    version: String,
}

/// Phase 1 replaces this with the real sensors run offline against the recording.
fn inventory_stub(_dir: &Path) -> Vec<Observed> {
    Vec::new()
}

#[derive(Debug, PartialEq)]
struct Score {
    services: usize,
    found: usize,
    versions_known: usize,
    versions_right: usize,
    extra: usize,
    missing: Vec<String>,
    wrong: Vec<(String, String, String)>,
}

fn normalise(v: &str) -> String {
    let t = v.trim();
    t.strip_prefix(['v', 'V']).unwrap_or(t).to_string()
}

fn score(setup: &Setup, observed: &[Observed]) -> Score {
    let seen: BTreeMap<&str, String> = observed
        .iter()
        .map(|o| (o.id.as_str(), normalise(&o.version)))
        .collect();
    let truth: BTreeSet<&str> = setup.services.iter().map(|s| s.id.as_str()).collect();
    let mut sc = Score {
        services: setup.services.len(),
        found: 0,
        versions_known: 0,
        versions_right: 0,
        extra: seen.keys().filter(|k| !truth.contains(*k)).count(),
        missing: Vec::new(),
        wrong: Vec::new(),
    };
    for s in &setup.services {
        let known = s.version != "unknown";
        if known {
            sc.versions_known += 1;
        }
        match seen.get(s.id.as_str()) {
            None => sc.missing.push(s.id.clone()),
            Some(v) => {
                sc.found += 1;
                if known {
                    if *v == s.version {
                        sc.versions_right += 1;
                    } else {
                        sc.wrong.push((s.id.clone(), s.version.clone(), v.clone()));
                    }
                }
            }
        }
    }
    sc.missing.sort();
    sc.wrong.sort();
    sc
}

fn pct(n: usize, d: usize) -> String {
    if d == 0 {
        return "n/a".into();
    }
    let pm = n * 1000 / d;
    format!("{}.{}%", pm / 10, pm % 10)
}

fn setup_dirs(root: &Path) -> Vec<String> {
    let Ok(rd) = fs::read_dir(root) else {
        return Vec::new();
    };
    let mut v: Vec<String> = rd
        .map(|e| e.unwrap().path())
        .filter(|p| p.is_dir())
        .map(|p| p.file_name().unwrap().to_string_lossy().into_owned())
        .collect();
    v.sort();
    v
}

#[test]
fn judge_a_recorded_setups() {
    let root = repo("fixtures/setups");
    let names = setup_dirs(&root);
    assert_eq!(
        names,
        EXPECTED_SETUPS.to_vec(),
        "the committed setups changed: update EXPECTED_SETUPS and BASELINE with the reason"
    );
    println!("JUDGE A BASELINE");
    let (mut services, mut found, mut known, mut right, mut extra) = (0, 0, 0, 0, 0);
    let mut platforms = BTreeSet::new();
    for name in &names {
        let dir = root.join(name);
        let setup = load_setup(&dir).unwrap_or_else(|e| panic!("{name}: {e}"));
        assert_ne!(setup.source, "synthetic", "{name}: synthetic in fixtures");
        check_fixture_source(&setup).unwrap();
        let sc = score(&setup, &inventory_stub(&dir));
        let row = (
            sc.services,
            sc.found,
            sc.versions_known,
            sc.versions_right,
            sc.extra,
        );
        let base = BASELINE.iter().find(|b| b.0 == name.as_str());
        assert!(
            base.is_some_and(|b| (b.1, b.2, b.3, b.4, b.5) == row),
            "Judge A moved for {name}: update BASELINE in the same PR with the reason"
        );
        println!(
            "{name} {}: found {}/{} ({}), versions {}/{} ({}), extra {}, missing {:?}",
            setup.platform,
            sc.found,
            sc.services,
            pct(sc.found, sc.services),
            sc.versions_right,
            sc.versions_known,
            pct(sc.versions_right, sc.versions_known),
            sc.extra,
            sc.missing
        );
        services += sc.services;
        found += sc.found;
        known += sc.versions_known;
        right += sc.versions_right;
        extra += sc.extra;
        platforms.insert(setup.platform);
    }
    println!(
        "total: found {found}/{services} ({}), versions {right}/{known} ({}), extra {extra}",
        pct(found, services),
        pct(right, known)
    );
    let none: Vec<&str> = PLATFORMS
        .iter()
        .filter(|(p, _)| !platforms.contains(*p))
        .map(|(_, label)| *label)
        .collect();
    println!("no recording yet: {}", none.join(", "));

    // Private recordings (the maintainer's own node): scored locally, never in the baseline.
    let private = repo("fixtures/private-setups");
    check_private_setups(&private).unwrap_or_else(|e| panic!("{e}"));
    for name in setup_dirs(&private) {
        let dir = private.join(&name);
        let setup = load_setup(&dir).unwrap_or_else(|e| panic!("private {name}: {e}"));
        let sc = score(&setup, &inventory_stub(&dir));
        println!(
            "private {name} {}: found {}/{} ({}), versions {}/{} ({}), extra {} (not in the baseline)",
            setup.platform,
            sc.found,
            sc.services,
            pct(sc.found, sc.services),
            sc.versions_right,
            sc.versions_known,
            pct(sc.versions_right, sc.versions_known),
            sc.extra
        );
    }
}

#[test]
fn fixtures_readme_lists_every_platform() {
    let readme = fs::read_to_string(repo("fixtures/README.md")).unwrap();
    let root = repo("fixtures/setups");
    let mut have = BTreeSet::new();
    for name in setup_dirs(&root) {
        have.insert(load_setup(&root.join(name)).unwrap().platform);
    }
    for (platform, label) in PLATFORMS {
        let prefix = format!("| {label} |");
        let row = readme
            .lines()
            .find(|l| l.starts_with(&prefix))
            .unwrap_or_else(|| panic!("fixtures/README.md has no table row for {label}"));
        assert_eq!(
            row.contains("no recording yet"),
            !have.contains(platform),
            "{label}: the README row and fixtures/setups disagree"
        );
    }
}

fn synthetic() -> PathBuf {
    repo("tests/synthetic/setup")
}

fn obs(list: &[(&str, &str)]) -> Vec<Observed> {
    list.iter()
        .map(|(i, v)| Observed {
            id: i.to_string(),
            version: v.to_string(),
        })
        .collect()
}

#[test]
fn the_scorer_counts_exactly() {
    let setup = load_setup(&synthetic()).unwrap();
    assert_eq!(setup.source, "synthetic");
    let stub = score(&setup, &inventory_stub(&synthetic()));
    assert_eq!(
        (
            stub.services,
            stub.found,
            stub.versions_known,
            stub.versions_right,
            stub.extra
        ),
        (5, 0, 4, 0, 0)
    );
    let truth: Vec<Observed> = setup
        .services
        .iter()
        .map(|s| Observed {
            id: s.id.clone(),
            version: s.version.clone(),
        })
        .collect();
    let oracle = score(&setup, &truth);
    assert_eq!(
        (
            oracle.services,
            oracle.found,
            oracle.versions_known,
            oracle.versions_right,
            oracle.extra
        ),
        (5, 5, 4, 4, 0)
    );
    let half = score(
        &setup,
        &obs(&[
            ("bitcoin-core", "v29.1"),
            ("tor", "0.4.8.16"),
            ("lnd", "0.19.1-beta"),
            ("electrs", "0.10.9"),
        ]),
    );
    assert_eq!(half.found, 3);
    assert_eq!(half.versions_known, 4);
    assert_eq!(half.versions_right, 2);
    assert_eq!(half.extra, 1);
    assert_eq!(half.missing, vec!["core-lightning", "strfry"]);
    assert_eq!(
        half.wrong,
        vec![(
            "lnd".to_string(),
            "0.19.2-beta".to_string(),
            "0.19.1-beta".to_string()
        )]
    );
}

fn copy_dir(from: &Path, to: &Path) {
    fs::create_dir_all(to).unwrap();
    for e in fs::read_dir(from).unwrap() {
        let p = e.unwrap().path();
        let dest = to.join(p.file_name().unwrap());
        if p.is_dir() {
            copy_dir(&p, &dest);
        } else {
            fs::copy(&p, &dest).unwrap();
        }
    }
}

#[test]
fn manifest_rules_reject_broken_setups() {
    // (case, mutation of manifest.toml as (from, to), words the error must hold)
    let text_cases: [(&str, &str, &str, &str); 9] = [
        (
            "topkey",
            "format = 1\n",
            "format = 1\nextra = 1\n",
            "unknown key",
        ),
        ("format", "format = 1", "format = 2", "format"),
        (
            "platform",
            "platform = \"raspiblitz\"",
            "platform = \"windows\"",
            "platform",
        ),
        (
            "recorded",
            "recorded = \"2026-11-16\"",
            "recorded = \"2026-02-30\"",
            "recorded",
        ),
        ("dup", "id = \"lnd\"", "id = \"bitcoin-core\"", "duplicate"),
        (
            "slug",
            "id = \"core-lightning\"",
            "id = \"Core_Lightning\"",
            "id",
        ),
        (
            "version",
            "version = \"29.1\"",
            "version = \"v29.1\"",
            "version",
        ),
        (
            "evidence-dots",
            "evidence = [\"replies/strfry/nip11.json\"]",
            "evidence = [\"../x\"]",
            "evidence",
        ),
        ("reviewer", "reviewed_by = \"test\"\n", "", "reviewed_by"),
    ];
    for (case, from, to, words) in text_cases {
        let dir = work("manifest", case);
        copy_dir(&synthetic(), &dir);
        let m = fs::read_to_string(dir.join("manifest.toml")).unwrap();
        assert!(m.contains(from), "{case}: the mutation does not apply");
        fs::write(dir.join("manifest.toml"), m.replacen(from, to, 1)).unwrap();
        let err = load_setup(&dir).expect_err(case);
        assert!(err.contains(words), "{case}: `{err}` lacks `{words}`");
    }
    let dir = work("manifest", "evidence-missing");
    copy_dir(&synthetic(), &dir);
    fs::remove_file(dir.join("systemctl-list-units.txt")).unwrap();
    assert!(load_setup(&dir).unwrap_err().contains("evidence"));

    let dir = work("manifest", "extra-file");
    copy_dir(&synthetic(), &dir);
    fs::write(dir.join("notes.txt"), "x").unwrap();
    assert!(
        load_setup(&dir)
            .unwrap_err()
            .contains("not a recording file")
    );

    let dir = work("manifest", "no-log");
    copy_dir(&synthetic(), &dir);
    fs::remove_file(dir.join("record-log.txt")).unwrap();
    assert!(load_setup(&dir).unwrap_err().contains("record-log.txt"));

    let dir = work("manifest", "test-tools");
    copy_dir(&synthetic(), &dir);
    let log = fs::read_to_string(dir.join("record-log.txt")).unwrap();
    fs::write(
        dir.join("record-log.txt"),
        log.replacen("mode record", "mode record test-tools", 1),
    )
    .unwrap();
    assert!(
        load_setup(&dir)
            .unwrap_err()
            .contains("test-tools recording")
    );

    // The judge's fixtures check refuses a synthetic setup.
    let setup = load_setup(&synthetic()).unwrap();
    assert!(check_fixture_source(&setup).is_err());
    let dir = work("manifest", "lab");
    copy_dir(&synthetic(), &dir);
    let m = fs::read_to_string(dir.join("manifest.toml")).unwrap();
    fs::write(dir.join("manifest.toml"), m.replacen("synthetic", "lab", 1)).unwrap();
    assert!(check_fixture_source(&load_setup(&dir).unwrap()).is_ok());
}

fn work(test: &str, case: &str) -> PathBuf {
    let dir = Path::new(env!("CARGO_TARGET_TMPDIR"))
        .join("ja")
        .join(test)
        .join(case);
    let _ = fs::remove_dir_all(&dir);
    fs::create_dir_all(&dir).unwrap();
    dir
}

// ---------- the leak lint ----------

fn script_list(begin: &str, end: &str) -> Vec<String> {
    let text = fs::read_to_string(repo("tools/record-setup.sh")).unwrap();
    let mut on = false;
    let mut out = Vec::new();
    for line in text.lines() {
        if line == begin {
            on = true;
        } else if line == end {
            on = false;
        } else if on {
            out.push(line.trim_start_matches("# ").to_string());
        }
    }
    assert!(!out.is_empty(), "no list between {begin} and {end}");
    out
}

fn short(s: &str) -> String {
    format!("{}…", s.chars().take(12).collect::<String>())
}

/// Maximal runs of hex digits: (start, text).
fn hex_runs(text: &str) -> Vec<(usize, &str)> {
    Regex::new(r"[0-9A-Fa-f]+")
        .unwrap()
        .find_iter(text)
        .map(|m| (m.start(), m.as_str()))
        .collect()
}

fn parse_v4(s: &str) -> Option<[u32; 4]> {
    let parts: Vec<&str> = s.split('.').collect();
    if parts.len() != 4 || parts.iter().any(|p| p.is_empty() || p.len() > 3) {
        return None;
    }
    let mut o = [0u32; 4];
    for (i, p) in parts.iter().enumerate() {
        o[i] = p.parse().ok()?;
        if o[i] > 255 {
            return None;
        }
    }
    Some(o)
}

fn v4_allowed(o: [u32; 4]) -> bool {
    let net = (o[0], o[1], o[2]);
    o[0] == 0
        || o[0] == 127
        || o[0] >= 224
        || net == (203, 0, 113)
        || net == (198, 51, 100)
        || net == (192, 0, 2)
        || (o[0] == 10 && o[1] == 200)
}

fn parse_v6(s: &str) -> Option<[u16; 8]> {
    if s.contains(":::") {
        return None;
    }
    let group = |g: &str| -> Option<u16> {
        if g.is_empty() || g.len() > 4 {
            return None;
        }
        u16::from_str_radix(g, 16).ok()
    };
    let halves: Vec<&str> = s.split("::").collect();
    let groups: Vec<u16> = match halves.as_slice() {
        [whole] => {
            let g: Option<Vec<u16>> = whole.split(':').map(group).collect();
            let g = g?;
            if g.len() != 8 {
                return None;
            }
            g
        }
        [l, r] => {
            let left: Option<Vec<u16>> = if l.is_empty() {
                Some(vec![])
            } else {
                l.split(':').map(group).collect()
            };
            let right: Option<Vec<u16>> = if r.is_empty() {
                Some(vec![])
            } else {
                r.split(':').map(group).collect()
            };
            let (left, right) = (left?, right?);
            if left.len() + right.len() > 7 {
                return None;
            }
            let mut g = left.clone();
            g.extend(std::iter::repeat_n(0, 8 - left.len() - right.len()));
            g.extend(right);
            g
        }
        _ => return None,
    };
    let mut out = [0u16; 8];
    out.copy_from_slice(&groups);
    Some(out)
}

fn v6_allowed(g: [u16; 8]) -> bool {
    let rest_zero = |from: usize, to: usize| g[from..to].iter().all(|x| *x == 0);
    (rest_zero(0, 8))
        || (rest_zero(0, 7) && g[7] == 1)
        || g[0] >= 0xff00
        || (g[0] == 0x2001 && g[1] == 0x0db8)
        || (g[0] == 0xfd00 && rest_zero(1, 7))
        || (g[0] == 0xfe80 && rest_zero(1, 7))
}

/// Last labels that are file extensions or unit types, not domains, and the
/// reserved suffixes. Same list as layer 2 of the recorder.
const NOT_DOMAIN: [&str; 22] = [
    "service",
    "socket",
    "target",
    "timer",
    "mount",
    "path",
    "slice",
    "scope",
    "device",
    "swap",
    "yml",
    "yaml",
    "json",
    "toml",
    "conf",
    "txt",
    "git",
    "log",
    "example",
    "invalid",
    "test",
    "localhost",
];

fn is_alpha_label(s: &str) -> bool {
    (2..=63).contains(&s.len()) && s.chars().all(|c| c.is_ascii_alphabetic())
}

fn is_base58(c: char) -> bool {
    c.is_ascii_alphanumeric() && !"0OIl".contains(c)
}

/// The files the recorder reads as tables, line by line: a row of a table is never
/// a mnemonic, and the lines of one must not chain into one.
fn is_table_file(rel: &str) -> bool {
    matches!(
        rel,
        "systemctl-list-units.txt"
            | "dpkg-query.txt"
            | "ss-tlnp.txt"
            | "ss-ulnp.txt"
            | "torrc"
            | "raspiblitz-conf.txt"
            | "raspiblitz-info.txt"
            | "raspiblitz-version.txt"
            | "record-log.txt"
            | "manifest.toml"
    ) || rel.ends_with("umbrel-app.yml")
}

fn is_space_like(c: char) -> bool {
    c.is_whitespace()
        || c == ','
        || ('\u{200B}'..='\u{200D}').contains(&c)
        || c == '\u{2060}'
        || c == '\u{FEFF}'
}

/// How the separators of a mnemonic are read. `General` is free text (the version
/// output, every JSON value). A table file is read twice, as the recorder does:
/// `Ws` (white space and commas of any length, line breaks included) and `Line`
/// (the 1 to 3 character form, never across a line break), so the lines of a
/// table do not chain into one run.
#[derive(Clone, Copy, PartialEq)]
enum SepMode {
    General,
    Ws,
    Line,
}

/// Can `sep` (a run of characters that are not letters or digits) sit between two
/// words of a mnemonic?
fn sep_ok(sep: &str, mode: SepMode) -> bool {
    let spaces = sep.chars().all(is_space_like);
    let n = sep.chars().count();
    let line_break = sep.contains(['\n', '\r']);
    match mode {
        SepMode::General => spaces || n <= 3,
        SepMode::Ws => spaces,
        SepMode::Line => !line_break && (spaces || n <= 3),
    }
}

/// Before a list number: white space or an opening bracket, 1 to 3 characters.
/// After it: a dot, a closing bracket or a colon first, 3 characters at most.
/// (The "-1 " of a placeholder such as `REDACTED-ADDRESS-1` is not a list number.)
fn num_sep_ok(sep: &str, mode: SepMode, before: bool) -> bool {
    let n = sep.chars().count();
    let shape = if before {
        sep.chars()
            .all(|c| is_space_like(c) || c == '(' || c == '[')
    } else {
        sep.starts_with(['.', ')', ']', ':'])
    };
    let line_ok = !sep.contains(['\n', '\r']);
    match mode {
        SepMode::General => shape && n <= 3,
        SepMode::Ws => false,
        SepMode::Line => shape && n <= 3 && line_ok,
    }
}

/// 12 or more words of 3 to 8 letters (every BIP39 English word fits) joined by
/// white space or commas of any length, or by 1 to 3 characters that are not
/// letters or digits (a dash, an underscore, a colon, a dot, a slash, a bar, any
/// mix), with an optional list number ("1. word 2) word"). In a table file the
/// 1 to 3 form does not cross a line break. No stop-word exemption.
fn has_seed_words(text: &str, table: bool) -> Option<String> {
    if table {
        scan_seed_words(text, SepMode::Ws).or_else(|| scan_seed_words(text, SepMode::Line))
    } else {
        scan_seed_words(text, SepMode::General)
    }
}

fn scan_seed_words(text: &str, mode: SepMode) -> Option<String> {
    // Runs of ASCII letters and digits, and runs of anything else.
    let mut toks: Vec<(bool, &str)> = Vec::new();
    let mut start = 0;
    let mut cur: Option<bool> = None;
    for (i, c) in text.char_indices() {
        let alnum = c.is_ascii_alphanumeric();
        match cur {
            Some(k) if k == alnum => {}
            Some(k) => {
                toks.push((k, &text[start..i]));
                start = i;
                cur = Some(alnum);
            }
            None => {
                start = i;
                cur = Some(alnum);
            }
        }
    }
    if let Some(k) = cur {
        toks.push((k, &text[start..]));
    }
    let is_word = |i: usize| {
        toks.get(i).is_some_and(|(a, t)| {
            *a && (3..=8).contains(&t.len()) && t.bytes().all(|b| b.is_ascii_alphabetic())
        })
    };
    let is_num = |i: usize| {
        toks.get(i).is_some_and(|(a, t)| {
            *a && (1..=2).contains(&t.len()) && t.bytes().all(|b| b.is_ascii_digit())
        })
    };
    let plain = |i: usize| toks.get(i).is_some_and(|(a, t)| !*a && sep_ok(t, mode));
    let numsep = |i: usize, before: bool| {
        toks.get(i)
            .is_some_and(|(a, t)| !*a && num_sep_ok(t, mode, before))
    };
    let mut i = 0;
    while i < toks.len() {
        if !is_word(i) {
            i += 1;
            continue;
        }
        let first = toks[i].1;
        let mut count = 1;
        let mut j = i;
        loop {
            if plain(j + 1) && is_word(j + 2) {
                count += 1;
                j += 2;
            } else if numsep(j + 1, true) && is_num(j + 2) && numsep(j + 3, false) && is_word(j + 4)
            {
                count += 1;
                j += 4;
            } else {
                break;
            }
        }
        if count >= 12 {
            return Some(first.to_string());
        }
        i = j + 1;
    }
    None
}

/// The 17 checks of the leak lint. The recorder's placeholders are not key-shaped,
/// so no check trusts a prefix.
fn leaks(rel_path: &str, text: &str) -> Vec<(&'static str, String)> {
    leaks_in(rel_path, text, false)
}

/// Same, for one string; `digest_field` says the string is the value of a typed
/// digest field of a Docker file (`Id`, `ImageID`, `RepoDigests`),
/// the only place a `sha256:` digest is expected.
fn leaks_in(rel_path: &str, text: &str, digest_field: bool) -> Vec<(&'static str, String)> {
    let mut found: Vec<(&'static str, String)> = Vec::new();
    let kept = script_list("# BEGIN KEPT-DOMAINS", "# END KEPT-DOMAINS");

    // ipv4
    let re = Regex::new(r"\d{1,3}(?:\.\d{1,3}){3}").unwrap();
    for m in re.find_iter(text) {
        let before = text[..m.start()].chars().next_back();
        let after = text[m.end()..].chars().next();
        let bad_before = before.is_some_and(|c| c.is_ascii_alphanumeric() || c == '.');
        let next_digit = text[m.end()..]
            .chars()
            .nth(1)
            .is_some_and(|c| c.is_ascii_digit());
        let bad_after =
            after.is_some_and(|c| c.is_ascii_alphanumeric() || (c == '.' && next_digit));
        if bad_before || bad_after {
            continue;
        }
        let Some(o) = parse_v4(m.as_str()) else {
            continue;
        };
        if rel_path == "dpkg-query.txt" {
            let line_start = text[..m.start()].rfind('\n').map_or(0, |i| i + 1);
            if text[line_start..m.start()].matches('\t').count() == 1 {
                continue;
            }
        }
        if !v4_allowed(o) {
            found.push(("ipv4", short(m.as_str())));
        }
    }

    // ipv6
    let re = Regex::new(r"[0-9A-Fa-f:]*:(?:\d{1,3}\.){3}\d{1,3}|[0-9A-Fa-f:]+").unwrap();
    for m in re.find_iter(text) {
        let s = m.as_str();
        if s.matches(':').count() < 2 {
            continue;
        }
        if let Some(idx) = s.rfind(':').filter(|_| s.contains('.')) {
            let (head, tail) = s.split_at(idx + 1);
            let ok = head.eq_ignore_ascii_case("::ffff:") && parse_v4(tail).is_some_and(v4_allowed);
            if !ok {
                found.push(("ipv6", short(s)));
            }
            continue;
        }
        if let Some(g) = parse_v6(s)
            && !v6_allowed(g)
        {
            found.push(("ipv6", short(s)));
        }
    }

    // onion (any case)
    let re = Regex::new(r"(?i)([A-Za-z0-9]+)\.onion").unwrap();
    for c in re.captures_iter(text) {
        let label = c[1].to_ascii_lowercase();
        let base32 = label
            .chars()
            .all(|x| x.is_ascii_lowercase() || ('2'..='7').contains(&x));
        if base32 && (label.len() == 56 || label.len() == 16) {
            found.push(("onion", short(&c[1])));
        }
    }

    // xkey
    let re = Regex::new(r"[xtyzuvYZUV]p(?:ub|rv)[1-9A-HJ-NP-Za-km-z]{100,112}").unwrap();
    for m in re.find_iter(text) {
        found.push(("xkey", short(m.as_str())));
    }

    // nostr-bech32 (any case)
    let re = Regex::new(r"(?i)(?:npub|nsec|nprofile|nevent|naddr)1[02-9ac-hj-np-z]{20,}").unwrap();
    for m in re.find_iter(text) {
        found.push(("nostr-bech32", short(m.as_str())));
    }

    // hex64, node-pubkey, macaroon
    for (start, run) in hex_runs(text) {
        let lower = run.to_ascii_lowercase();
        let before = &text[..start];
        let typed_digest = digest_field
            && start + 64 == text.len()
            && (before == "sha256:" || before.ends_with("@sha256:"));
        if run.len() == 64 && !typed_digest {
            found.push(("hex64", short(run)));
        }
        if run.len() == 66 && (lower.starts_with("02") || lower.starts_with("03")) {
            found.push(("node-pubkey", short(run)));
        }
        if run.len() >= 100 && lower.starts_with("0201036c6e64") {
            found.push(("macaroon", short(run)));
        }
    }
    let re = Regex::new(r"AgEDbG5k[A-Za-z0-9+/_-]{32,}").unwrap();
    for m in re.find_iter(text) {
        found.push(("macaroon", short(m.as_str())));
    }

    // pem-private-key
    let re = Regex::new(r"-----BEGIN [A-Z ]*PRIVATE KEY-----").unwrap();
    for m in re.find_iter(text) {
        found.push(("pem-private-key", short(m.as_str())));
    }

    // home-user
    let re = Regex::new(r#"/(?:home|Users)/([^/\s"',;:\x00]+)(?:[/"'\s]|$)"#).unwrap();
    for c in re.captures_iter(text) {
        let u = c[1].to_ascii_lowercase();
        let placeholder = u
            .strip_prefix("user-")
            .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()));
        if !PLATFORM_DEFAULTS.contains(&u.as_str()) && !placeholder {
            found.push(("home-user", short(&c[1])));
        }
    }

    // email
    let re = Regex::new(r"[A-Za-z0-9._%+-]+@([A-Za-z0-9-]+(?:\.[A-Za-z0-9-]+)+)").unwrap();
    for c in re.captures_iter(text) {
        let domain = c[1].to_ascii_lowercase();
        let last = domain.rsplit('.').next().unwrap_or("");
        if is_alpha_label(last) && !NOT_DOMAIN.contains(&last) {
            found.push(("email", short(c.get(0).map_or("", |m| m.as_str()))));
        }
    }

    // domain: any name with an alphabetic last label, except file extensions,
    // unit types, reserved suffixes, the kept domains and the kept label keys
    let re = Regex::new(r"[A-Za-z0-9._-]+").unwrap();
    for m in re.find_iter(text) {
        let token = m.as_str().trim_matches('.');
        if !token.contains('.') || token.contains("..") {
            continue;
        }
        let lc = token.to_ascii_lowercase();
        let last = lc.rsplit('.').next().unwrap_or("");
        if !is_alpha_label(last) || NOT_DOMAIN.contains(&last) {
            continue;
        }
        let onion_placeholder = lc.starts_with("redacted-onion-")
            && lc.ends_with(".onion")
            && lc[15..lc.len() - 6].bytes().all(|b| b.is_ascii_digit());
        if kept.contains(&lc) || onion_placeholder || lc == "record-setup.sh" {
            continue;
        }
        found.push(("domain", short(token)));
    }

    // secret-kv: a secret-named key whose value is not a placeholder or a kept literal
    let re = Regex::new(
        r#"(?i)[A-Za-z0-9_.-]*(?:password|passwd|pass|secret|token|apikey|api_key|api-key|auth|rpcauth|rpcuser|macaroon|rune|cookie|seed|mnemonic|privkey|private_key|credential|hashedcontrolpassword)[A-Za-z0-9_.-]*["']?[ \t]*[=:][ \t]*("[^"\r\n]*"|'[^'\r\n]*'|[^\s,;"'{}\[\]]+)"#,
    )
    .unwrap();
    for c in re.captures_iter(text) {
        let v = c[1].trim_matches(['"', '\'']);
        let lower = v.to_ascii_lowercase();
        let placeholder = v
            .strip_prefix("REDACTED-SECRET-")
            .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()));
        let literal = [
            "", "0", "1", "on", "off", "true", "false", "auto", "yes", "no",
        ]
        .contains(&lower.as_str());
        let scheme = lower == "bearer" || lower == "basic";
        if !placeholder && !literal && !scheme {
            found.push(("secret-kv", short(&c[0])));
        }
    }

    // basic-auth
    let re = Regex::new(r"(?i)\bbasic[ \t]+([A-Za-z0-9+/=._~-]+)").unwrap();
    for c in re.captures_iter(text) {
        let v = &c[1];
        let placeholder = v
            .strip_prefix("REDACTED-BEARER-")
            .is_some_and(|n| !n.is_empty() && n.bytes().all(|b| b.is_ascii_digit()));
        if !placeholder {
            found.push(("basic-auth", short(v)));
        }
    }

    // seed-words
    if let Some(first) = has_seed_words(text, is_table_file(rel_path)) {
        found.push(("seed-words", short(&first)));
    }

    // wif: a 51 or 52 character base58 run starting 5, K, L, c or 9
    let re = Regex::new(r"[A-Za-z0-9]+").unwrap();
    for m in re.find_iter(text) {
        let run = m.as_str();
        if (run.len() == 51 || run.len() == 52)
            && run.starts_with(['5', 'K', 'L', 'c', '9'])
            && run.chars().all(is_base58)
        {
            found.push(("wif", short(run)));
        }
    }

    // token: a run of 32 or more key characters holding upper, lower and a digit
    let re = Regex::new(r"[A-Za-z0-9_+=-]{32,}").unwrap();
    for m in re.find_iter(text) {
        let run = m.as_str();
        let mixed = run.chars().any(|c| c.is_ascii_uppercase())
            && run.chars().any(|c| c.is_ascii_lowercase())
            && run.chars().any(|c| c.is_ascii_digit());
        if mixed {
            found.push(("token", short(run)));
        }
    }
    found
}

fn files_of(dir: &Path) -> Vec<String> {
    let mut acc = Vec::new();
    collect_files(dir, dir, &mut acc);
    acc
}

/// Every string value with the name of the field it sits in (an array's
/// elements carry their array's field name).
fn json_strings(v: &serde_json::Value, key: &str, out: &mut Vec<(String, String)>) {
    match v {
        serde_json::Value::String(s) => out.push((s.clone(), key.to_string())),
        serde_json::Value::Array(a) => a.iter().for_each(|x| json_strings(x, key, out)),
        serde_json::Value::Object(o) => o.iter().for_each(|(k, x)| json_strings(x, k, out)),
        _ => {}
    }
}

/// The JSON fields that hold free text (the recorder joins only these).
fn is_free_key(key: &str) -> bool {
    matches!(
        key,
        "version" | "commit" | "app_pre_release" | "build_tags" | "go_version" | "latest_version"
    ) || key.ends_with(".version")
        || key.ends_with(".revision")
}

/// Runs the lint over every file of a setup folder: (file, check, shortened token).
fn lint_tree(dir: &Path) -> Vec<(String, &'static str, String)> {
    let mut all = Vec::new();
    for rel in files_of(dir) {
        let bytes = fs::read(dir.join(&rel)).unwrap();
        let text = String::from_utf8_lossy(&bytes).into_owned();
        // JSON is read by its values: a key is a field name, a value can be a leak.
        let pieces: Vec<(String, String)> = match serde_json::from_str::<serde_json::Value>(&text) {
            Ok(v) if rel.ends_with(".json") => {
                let mut strings = Vec::new();
                json_strings(&v, "", &mut strings);
                strings
            }
            _ => vec![(text, String::new())],
        };
        let docker = rel == "docker-ps.json" || rel == "docker-images.json";
        // A mnemonic split across several values of one JSON file.
        // Only fields that hold free text are joined; enums, ports, names and
        // addresses never are.
        let free: Vec<&str> = pieces
            .iter()
            .filter(|(_, k)| is_free_key(k))
            .map(|(s, _)| s.as_str())
            .collect();
        let from_json = rel.ends_with(".json") && free.len() > 1;
        let joined = free.join(" ");
        let before = all.len();
        for (piece, key) in pieces {
            let typed = docker
                && (["Id", "ImageID", "RepoDigests"].contains(&key.as_str())
                    || (rel == "docker-ps.json" && key == "Image"));
            for (check, token) in leaks_in(&rel, &piece, typed) {
                all.push((rel.clone(), check, token));
            }
        }
        let flagged = all[before..].iter().any(|(_, c, _)| *c == "seed-words");
        if from_json
            && !flagged
            && let Some(first) = has_seed_words(&joined, false)
        {
            all.push((rel.clone(), "seed-words", short(&first)));
        }
    }
    all
}

/// Loads and lints every private setup under `root`. The message names the file
/// and the check, never the value.
fn check_private_setups(root: &Path) -> Result<(), String> {
    for name in setup_dirs(root) {
        let dir = root.join(&name);
        load_setup(&dir).map_err(|e| format!("private setup {name}: {e}"))?;
        if let Some((file, check, _)) = lint_tree(&dir).into_iter().next() {
            return Err(format!(
                "private setup {name}: {file} trips the {check} check"
            ));
        }
    }
    Ok(())
}

#[test]
fn no_recording_leaks_a_secret_shape() {
    let mut dirs: Vec<PathBuf> = setup_dirs(&repo("fixtures/setups"))
        .into_iter()
        .map(|n| repo("fixtures/setups").join(n))
        .collect();
    dirs.push(synthetic());
    dirs.push(repo("tests/synthetic/record-setup/expected"));
    for dir in dirs {
        let l = lint_tree(&dir);
        assert!(l.is_empty(), "{} holds secret shapes: {l:?}", dir.display());
    }
}

const CHECKS: [&str; 17] = [
    "ipv4",
    "ipv6",
    "onion",
    "xkey",
    "nostr-bech32",
    "hex64",
    "node-pubkey",
    "macaroon",
    "pem-private-key",
    "home-user",
    "email",
    "domain",
    "secret-kv",
    "basic-auth",
    "seed-words",
    "wif",
    "token",
];

#[test]
fn the_leak_lint_has_teeth() {
    let dir = repo("tests/synthetic/record-setup/raw");
    let mut counts: BTreeMap<&str, usize> = CHECKS.into_iter().map(|k| (k, 0)).collect();
    for (_, check, _) in lint_tree(&dir) {
        *counts.entry(check).or_insert(0) += 1;
    }
    println!("leak lint teeth: {counts:?}");
    assert_eq!(counts.len(), 17);
    for (check, n) in &counts {
        assert!(
            *n > 0,
            "the {check} check never fired on the raw synthetic input"
        );
    }
}

/// Codex HIGH: a hidden file in a setup folder bypassed the judge.
#[test]
fn regression_hidden_files_are_rejected() {
    let dir = work("hidden", "dotfile");
    copy_dir(&synthetic(), &dir);
    let bech = "qpzry9x8gf2tvdw0s3jn54khce6mua7l".repeat(2);
    fs::write(dir.join(".notes"), format!("nsec1{}", &bech[..58])).unwrap();
    assert!(
        load_setup(&dir)
            .unwrap_err()
            .contains("not a recording file")
    );
    let found = lint_tree(&dir);
    assert!(
        found
            .iter()
            .any(|(f, c, _)| f == ".notes" && *c == "nostr-bech32"),
        "{found:?}"
    );
}

/// Codex MED: private setups were scored but never linted.
#[test]
fn regression_private_setups_are_linted() {
    let root = work("private", "root");
    let dir = root.join("mynode");
    copy_dir(&synthetic(), &dir);
    assert!(check_private_setups(&root).is_ok());
    let units = dir.join("systemctl-list-units.txt");
    let mut text = fs::read_to_string(&units).unwrap();
    text.push_str("rpcpassword=Zq9x\n");
    fs::write(&units, text).unwrap();
    let found = lint_tree(&dir);
    assert!(found.iter().any(|(_, c, _)| *c == "secret-kv"), "{found:?}");
    let err = check_private_setups(&root).unwrap_err();
    assert!(err.contains("secret-kv") && !err.contains("Zq9x"), "{err}");
}

/// Codex MED: the lint missed short credentials, mnemonics, runes, WIF keys.
#[test]
fn regression_lint_catches_short_credentials() {
    let words =
        "cravat dolmen fennel gimlet hassock jerkin kirtle lintel mullet nimbus oriel plinth";
    let mnemonic = words.replace(' ', "\t");
    let b58 = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz";
    let wif = format!("K{}", &b58[..51]);
    let bech = "qpzry9x8gf2tvdw0s3jn54khce6mua7l".repeat(2);
    let nsec = format!("NSEC1{}", bech[..58].to_uppercase());
    let b32 = "abcdefghijklmnopqrstuvwxyz234567".repeat(2);
    let onion = format!("{}.ONION", b32[..56].to_uppercase());
    let cases: Vec<(String, &str)> = vec![
        ("rpcpassword=ab12".into(), "secret-kv"),
        ("Basic dTpw".into(), "basic-auth"),
        (mnemonic, "seed-words"),
        (
            "Rr9AbCdEfGhIjKlMnOpQrStUvWxYz0123456789abcdefghij".into(),
            "token",
        ),
        (wif, "wif"),
        (nsec, "nostr-bech32"),
        (onion, "onion"),
    ];
    for (text, check) in cases {
        let found = leaks("x.txt", &text);
        assert!(
            found.iter().any(|(c, _)| *c == check),
            "{check} did not fire on {text:?}: {found:?}"
        );
    }
}

/// Codex HIGH: the lint trusted the old placeholder shapes.
#[test]
fn regression_lint_has_no_placeholder_trust() {
    let nsec = format!("nsec1redacted{}xkttpr", "q".repeat(44));
    let hex = format!("de1e7ed{}1", "0".repeat(56));
    let node = format!("02de1e7ed{}1", "0".repeat(56));
    let xpub = format!("xpubRedacted{}2", "1".repeat(98));
    let wif = format!("KRedacted{}2", "1".repeat(42));
    let onion = format!("redacted{}b.onion", "a".repeat(47));
    for (text, check) in [
        (nsec, "nostr-bech32"),
        (hex, "hex64"),
        (node, "node-pubkey"),
        (xpub, "xkey"),
        (wif, "wif"),
        (onion, "onion"),
    ] {
        let found = leaks("x.txt", &text);
        assert!(found.iter().any(|(c, _)| *c == check), "{check}: {found:?}");
    }
    // The recorder's own placeholders are clean.
    let clean = "REDACTED-NSEC-1 REDACTED-XPUB-2 REDACTED-HEX64-3 REDACTED-NODEKEY-4 REDACTED-WIF-5 REDACTED-ONION-6.onion REDACTED-MAC-7";
    assert!(
        leaks("x.txt", clean).is_empty(),
        "{:?}",
        leaks("x.txt", clean)
    );
}

/// Codex MED: hyphen-delimited addresses, and mnemonics with a stop word or
/// no-break spaces.
#[test]
fn regression_lint_hyphen_address_and_nbsp_mnemonic() {
    let found = leaks("x.txt", "see ip-8.8.4.4-node");
    assert!(found.iter().any(|(c, _)| *c == "ipv4"), "{found:?}");
    let found = leaks("x.txt", "x_9.9.9.9_y");
    assert!(found.iter().any(|(c, _)| *c == "ipv4"), "{found:?}");
    let nbsp = format!("{} about", ["abandon"; 11].join("\u{a0}"));
    let found = leaks("x.txt", &nbsp);
    assert!(found.iter().any(|(c, _)| *c == "seed-words"), "{found:?}");
    let stop = format!("this {} acid", ["abandon"; 10].join(" "));
    let found = leaks("x.txt", &stop);
    assert!(found.iter().any(|(c, _)| *c == "seed-words"), "{found:?}");
}

/// Codex 3 HIGH: `sha256:` + 64 hex characters was exempt everywhere, so a
/// private-key scalar written that way passed. Only typed digest fields of the
/// Docker files are exempt.
#[test]
fn regression3_lint_digest_only_in_typed_fields() {
    let hex = "a1".repeat(32);
    let found = leaks("x.txt", &format!("sha256:{hex}"));
    assert!(found.iter().any(|(c, _)| *c == "hex64"), "{found:?}");

    let dir = work("lint3", "digest");
    let typed = format!(
        "[{{\"Id\":\"sha256:{hex}\",\"RepoDigests\":[\"docker.io/lightninglabs/lnd@sha256:{hex}\"]}}]"
    );
    fs::write(dir.join("docker-images.json"), typed).unwrap();
    assert!(lint_tree(&dir).is_empty(), "{:?}", lint_tree(&dir));

    // The same digest in a label value, a version field or another file is a leak.
    let label = format!(
        "[{{\"Id\":\"sha256:{hex}\",\"Labels\":{{\"org.opencontainers.image.version\":\"sha256:{hex}\"}}}}]"
    );
    fs::write(dir.join("docker-images.json"), label).unwrap();
    let found = lint_tree(&dir);
    assert_eq!(found.len(), 1, "{found:?}");
    assert_eq!(found[0].1, "hex64");
    fs::remove_file(dir.join("docker-images.json")).unwrap();
    fs::write(
        dir.join("getinfo.json"),
        format!("{{\"version\":\"sha256:{hex}\"}}"),
    )
    .unwrap();
    let found = lint_tree(&dir);
    assert!(found.iter().any(|(_, c, _)| *c == "hex64"), "{found:?}");
}

/// Codex 3 HIGH, pins for the lint: mixed white space in a mnemonic, and a
/// placeholder prefix in front of a key body.
#[test]
fn regression3_lint_mixed_whitespace_and_placeholder_prefix() {
    let wrapped = format!(
        "{} \n{} about",
        ["abandon"; 6].join(" "),
        ["abandon"; 5].join(" ")
    );
    let found = leaks("x.txt", &wrapped);
    assert!(found.iter().any(|(c, _)| *c == "seed-words"), "{found:?}");
    let key = format!("PASS=REDACTED-NSEC1{}SMHLTGL", "Q".repeat(51));
    let found = leaks("x.txt", &key);
    assert!(found.iter().any(|(c, _)| *c == "secret-kv"), "{found:?}");
    assert!(found.iter().any(|(c, _)| *c == "nostr-bech32"), "{found:?}");
}

/// Fourth review HIGH, for the lint: a mnemonic joined by 1 to 3 non-alphanumeric
/// characters (any mix), or written as a numbered list, in a kept field.
#[test]
fn regression4_lint_joined_mnemonic() {
    let words = [
        "legal", "winner", "thank", "year", "wave", "sausage", "worth", "useful", "legal",
        "winner", "thank", "yellow",
    ];
    let has_seed = |f: &[(&'static str, String)]| f.iter().any(|(c, _)| *c == "seed-words");
    for sep in [
        " ", "\t", ",", "-", "_", ":", ".", "/", "|", "\n", ", ", " - ", "::", "...",
    ] {
        let found = leaks("x.txt", &words.join(sep));
        assert!(has_seed(&found), "separator {sep:?}: {found:?}");
    }
    let mixed = [" ", "-", "_", ", ", ":", "|", "\t", "/", ".", "\n", " - "];
    let mut s = String::new();
    for (i, w) in words.iter().enumerate() {
        if i > 0 {
            s.push_str(mixed[(i - 1) % mixed.len()]);
        }
        s.push_str(w);
    }
    assert!(has_seed(&leaks("x.txt", &s)), "mixed separators");
    for style in [".", ")"] {
        let numbered: Vec<String> = words
            .iter()
            .enumerate()
            .map(|(i, w)| format!("{}{style} {w}", i + 1))
            .collect();
        assert!(
            has_seed(&leaks("x.txt", &numbered.join(" "))),
            "numbered {style}"
        );
        assert!(
            has_seed(&leaks("x.txt", &numbered.join("\n"))),
            "numbered lines {style}"
        );
    }
    // Eleven words are not a mnemonic.
    assert!(!has_seed(&leaks("x.txt", &words[..11].join("-"))));

    // A mnemonic split across two JSON values of one file.
    let dir = work("lint4", "split");
    fs::write(
        dir.join("getversion.json"),
        format!(
            "{{\"lnd\":{{\"build_tags\":[\"{}\",\"{}\"]}}}}",
            words[..6].join(" "),
            words[6..].join(" ")
        ),
    )
    .unwrap();
    let found = lint_tree(&dir);
    assert!(
        found.iter().any(|(_, c, _)| *c == "seed-words"),
        "{found:?}"
    );

    // Table files are read line by line: ordinary rows never chain into a mnemonic.
    let units: String = (0..8)
        .map(
            |_| "cron.service loaded active running Regular background program processing daemon\n",
        )
        .collect();
    assert!(!has_seed(&leaks("systemctl-list-units.txt", &units)));
    let conf: String = (0..16)
        .map(|_| "rtl=\"off\"\nlnd=\"off\"\ntor=\"off\"\n")
        .collect();
    assert!(!has_seed(&leaks("raspiblitz-conf.txt", &conf)));
}

/// Fourth review LOW, for the lint: `RepoTags` is not a digest field.
#[test]
fn regression4_lint_repotags_is_not_a_digest_field() {
    let hex = "c3".repeat(32);
    let dir = work("lint4", "repotags");
    fs::write(
        dir.join("docker-images.json"),
        format!("[{{\"RepoTags\":[\"sha256:{hex}\"]}}]"),
    )
    .unwrap();
    let found = lint_tree(&dir);
    assert!(found.iter().any(|(_, c, _)| *c == "hex64"), "{found:?}");
}

/// Fifth review HIGH 1 and MEDIUM 1, for the lint: a digest after `@` at the end
/// of a docker-ps `Image` is a digest field, and enum values (`tcp`, `running`)
/// are never joined into a phrase.
#[test]
fn regression5_lint_digest_pinned_image_and_enums() {
    let x = "d".repeat(64);
    let ports: Vec<String> = (0..12)
        .map(|i| format!("{{\"PrivatePort\":{},\"Type\":\"tcp\"}}", 8000 + i))
        .collect();
    let dir = work("lint5", "pinned");
    fs::write(
        dir.join("docker-ps.json"),
        format!(
            "[{{\"Names\":[\"/lnd\"],\"Image\":\"lightninglabs/lnd:v0.18.0-beta@sha256:{x}\",\"State\":\"running\",\"Ports\":[{}]}}]",
            ports.join(",")
        ),
    )
    .unwrap();
    let found = lint_tree(&dir);
    assert!(found.is_empty(), "{found:?}");
    // The same digest in a middle of an Image value is still a leak.
    fs::write(
        dir.join("docker-ps.json"),
        format!("[{{\"Image\":\"x-sha256:{x}-y\"}}]"),
    )
    .unwrap();
    let found = lint_tree(&dir);
    assert!(found.iter().any(|(_, c, _)| *c == "hex64"), "{found:?}");
}
