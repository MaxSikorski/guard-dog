//! The service catalog (`catalog/<id>.toml`), phase 1.4 step 1, and its loader
//! (`gd_core::catalog`).
//!
//! Deterministic: no network, no Docker, no clock. Entries are read in sorted
//! order. The format is documented in `catalog/README.md`. Every rule that needs
//! only the entry's own text lives in the loader (`catalog::load`, and
//! `catalog::load_all` across entries); the mutation tests here show the loader
//! refuses a broken entry. What stays in this file needs the repo on disk: that
//! an example's `source` file exists and an advisory example's version is in
//! that advisory, and the ties to three fixtures already in the repo: the
//! replies the lab recorded (`fixtures/lab-recorded/manifest.toml`), Judge B's
//! `[[product]]` table (`fixtures/expected-matches.toml`) and the lab's
//! services (`lab/compose.yml`). Also pinned here: the embedded file list
//! (`catalog_files.rs`) is exactly the `catalog/` folder.
//!
//! Each of those rules is a function that returns `Err(message)`, so the
//! mutation tests can show the rule refuses a broken entry.

// Test-only crate: helper functions panic as failed checks. See expected_matches.rs.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use gd_core::catalog::{
    self, Catalog, Entry, MAX_REPLY, Pattern, READ_ONLY_CALLS, SHARED_PORTS, normalise_image,
};
use regex::Regex;
use toml::{Table, Value};
use yaml_rust2::YamlLoader;

/// Judge B products with no catalog entry yet. Exact: the test fails when this
/// differs from the real gap in either direction, so it only shrinks by editing
/// it here. It shrinks as later pull requests add entries. Two products are
/// still held back: `coldcard` (the format cannot say which model or track a
/// version belongs to) and `xz-utils` (its version is read from a package
/// manager, not a service).
const UNCATALOGUED: [&str; 2] = ["coldcard", "xz-utils"];

/// The ids catalogued so far (PR 1, then PR 3). An id here must keep its entry
/// and can never appear in `UNCATALOGUED`, so the gap list cannot grow back. Add
/// to this list when entries land; never remove from it.
const CATALOGUED_BEFORE: [&str; 13] = [
    "alby-hub",
    "bitcoin-core",
    "btcpay-server",
    "core-lightning",
    "fedimintd",
    "gatewayd",
    "lightning-terminal",
    "lnd",
    "nutshell",
    "rtl",
    "strfry",
    "tapd",
    "umbrelos",
];

/// Catalog entries that are not in Judge B's product table yet. Exact, like the
/// lists above. Empty: every entry today is a Judge B product.
const NOT_YET_IN_JUDGE_B: [&str; 0] = [];

/// The lab's service names and the catalog id each one is. Exact: it must cover
/// every service in `lab/compose.yml` and every `# <svc> reported` line in the
/// recorded manifest.
const LAB_SERVICES: [(&str, &str); 5] = [
    ("bitcoind", "bitcoin-core"),
    ("lnd", "lnd"),
    ("cln", "core-lightning"),
    ("strfry", "strfry"),
    ("nutshell", "nutshell"),
];

const LAB_FILE: &str = "lab/compose.yml";

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(rel: &str) -> String {
    fs::read_to_string(root().join(rel)).unwrap_or_else(|e| panic!("read {rel}: {e}"))
}

/// Every `catalog/*.toml`, sorted by file name: (id from the file name, text).
fn entry_files() -> Vec<(String, String)> {
    let dir = root().join("catalog");
    let mut files: Vec<(String, String)> = Vec::new();
    for item in fs::read_dir(&dir).expect("catalog/ exists") {
        let path = item.unwrap().path();
        assert!(
            !path.is_dir(),
            "catalog/ is one flat folder, found a folder: {path:?}"
        );
        let name = path.file_name().unwrap().to_str().unwrap().to_string();
        if let Some(stem) = name.strip_suffix(".toml") {
            files.push((stem.to_string(), fs::read_to_string(&path).unwrap()));
        } else {
            assert_eq!(name, "README.md", "unexpected file in catalog/: {name}");
        }
    }
    files.sort();
    files
}

fn entries() -> BTreeMap<String, Table> {
    entry_files()
        .into_iter()
        .map(|(stem, text)| {
            let table = validate(&stem, &text).unwrap_or_else(|e| panic!("{e}"));
            (stem, table)
        })
        .collect()
}

fn string<'a>(t: &'a Table, k: &str, ctx: &str) -> Result<&'a str, String> {
    match t.get(k) {
        Some(Value::String(s)) => Ok(s),
        _ => Err(format!("{ctx}.{k} must be a string")),
    }
}

fn table<'a>(t: &'a Table, k: &str, ctx: &str) -> Result<&'a Table, String> {
    match t.get(k) {
        Some(Value::Table(x)) => Ok(x),
        _ => Err(format!("{ctx}.{k} must be a table")),
    }
}

fn tables<'a>(t: &'a Table, k: &str, ctx: &str) -> Result<Vec<&'a Table>, String> {
    match t.get(k) {
        None => Ok(Vec::new()),
        Some(Value::Array(a)) => a
            .iter()
            .map(|v| v.as_table().ok_or(format!("{ctx}.{k} must hold tables")))
            .collect(),
        _ => Err(format!("{ctx}.{k} must be a list of tables")),
    }
}

fn strings<'a>(t: &'a Table, k: &str, ctx: &str) -> Result<Vec<&'a str>, String> {
    match t.get(k) {
        Some(Value::Array(a)) => a
            .iter()
            .map(|v| v.as_str().ok_or(format!("{ctx}.{k} must hold strings")))
            .collect(),
        _ => Err(format!("{ctx}.{k} must be a list of strings")),
    }
}

/// Every per-file rule: the loader's, then the ones that need the repo on
/// disk. Returns the parsed table.
fn validate(stem: &str, text: &str) -> Result<Table, String> {
    let entry = catalog::load(stem, text).map_err(|e| e.to_string())?;
    check_files(&entry).map_err(|e| format!("{stem}: {e}"))?;
    toml::from_str(text).map_err(|e| format!("{stem}: not valid TOML: {e}"))
}

/// A `source` is a file in the repo or an https URL (the loader checked the
/// URL is under the upstream and the file name has no `..`).
fn source_exists(field: &str, src: &str) -> Result<(), String> {
    if src.starts_with("https://") || root().join(src).is_file() {
        Ok(())
    } else {
        Err(format!(
            "{field} must be a file in the repo or a URL under the upstream: {src}"
        ))
    }
}

/// The checks that read files: every port and example source exists, and an
/// advisory example's version is in that advisory.
fn check_files(e: &Entry) -> Result<(), String> {
    for p in &e.recognize.ports {
        if let Some(s) = &p.source {
            source_exists("recognize.ports.source", s)?;
        }
    }
    for ex in &e.version.examples {
        source_exists("version.examples.source", &ex.source)?;
        if ex.advisory {
            advisory_has_version(&ex.source, &ex.version, &e.advisories.osv_packages)?;
        }
    }
    Ok(())
}

/// Does the advisory file say `want` is an introduced, fixed or last-affected version of
/// one of the entry's own OSV packages (`<ECOSYSTEM> <name>`)? The file is parsed, not searched.
fn advisory_has_version(src: &str, want: &str, osv_packages: &[String]) -> Result<(), String> {
    let doc: serde_json::Value =
        serde_json::from_str(&read(src)).map_err(|e| format!("{src} is not valid JSON: {e}"))?;
    let affected = doc.get("affected").and_then(|a| a.as_array());
    for a in affected.into_iter().flatten() {
        let pkg = a.get("package");
        let name = |k: &str| pkg.and_then(|p| p.get(k)).and_then(|v| v.as_str());
        let (Some(eco), Some(n)) = (name("ecosystem"), name("name")) else {
            continue;
        };
        if !osv_packages.contains(&format!("{eco} {n}")) {
            continue;
        }
        let mut found: Vec<&str> = Vec::new();
        for r in a
            .get("ranges")
            .and_then(|r| r.as_array())
            .into_iter()
            .flatten()
        {
            for ev in r
                .get("events")
                .and_then(|e| e.as_array())
                .into_iter()
                .flatten()
            {
                for k in ["introduced", "fixed", "last_affected"] {
                    found.extend(ev.get(k).and_then(|v| v.as_str()));
                }
            }
        }
        let fixed_in = a.get("database_specific").and_then(|d| d.get("fixed_in"));
        for v in fixed_in.and_then(|f| f.as_array()).into_iter().flatten() {
            found.extend(v.as_str());
        }
        if found.contains(&want) {
            return Ok(());
        }
    }
    Err(format!(
        "`{want}` is not an introduced, fixed or last-affected version of this entry's osv_packages in {src}"
    ))
}

fn version_regex(v: &Table) -> Result<Pattern, String> {
    Pattern::new_version(string(v, "regex", "version")?)
}

/// Runs a version regex on a raw reply. Replies over `MAX_REPLY` bytes are refused.
fn extract(re: &Pattern, raw: &str) -> Option<String> {
    re.version(raw).map(str::to_string)
}

// ---------- cross-source checks ----------

struct Recorded {
    service: String,
    id: String,
    raw: String,
    version: String,
}

/// Reads the `# <svc> reported "<raw>" (...)` comments and the `[[service]]`
/// block that follows each one from the lab's recorded manifest.
fn recordings(text: &str) -> Vec<Recorded> {
    let head = Regex::new(r#"^# ([a-z0-9-]+) reported "([^"]*)" \("#).unwrap();
    let kv = |l: &str, key: &str| -> Option<String> {
        let rest = l.strip_prefix(key)?.strip_prefix(" = \"")?;
        Some(rest.strip_suffix('"')?.to_string())
    };
    let mut out = Vec::new();
    let mut pending: Option<(String, String)> = None;
    let mut id: Option<String> = None;
    for l in text.lines() {
        if let Some(c) = head.captures(l) {
            pending = Some((c[1].to_string(), c[2].to_string()));
            id = None;
        } else if let Some(i) = kv(l, "id") {
            id = Some(i);
        } else if let Some(ver) = kv(l, "version") {
            let (service, raw) = pending
                .take()
                .expect("a version line follows a reported line");
            out.push(Recorded {
                service,
                id: id.take().expect("an id line comes first"),
                raw,
                version: ver,
            });
        }
    }
    out
}

fn lab_id(service: &str) -> Option<&'static str> {
    LAB_SERVICES
        .iter()
        .find(|(s, _)| *s == service)
        .map(|(_, id)| *id)
}

/// Every recorded reply has a mapped lab service, an entry, and a regex that
/// gives the recorded version; every lab service has a recording (no silent skip).
fn check_recordings(entries: &BTreeMap<String, Table>, rec: &[Recorded]) -> Result<(), String> {
    for (svc, _) in LAB_SERVICES {
        if !rec.iter().any(|r| r.service == svc) {
            return Err(format!("lab service `{svc}` has no recorded reply"));
        }
    }
    for r in rec {
        let id = lab_id(&r.service).ok_or(format!(
            "recorded service `{}` is not in LAB_SERVICES",
            r.service
        ))?;
        if id != r.id {
            return Err(format!(
                "recorded `{}` is id `{}` but LAB_SERVICES says `{id}`",
                r.service, r.id
            ));
        }
        let entry = entries
            .get(id)
            .ok_or(format!("recorded service `{id}` has no catalog entry"))?;
        let re = version_regex(table(entry, "version", id)?)?;
        let got = extract(&re, &r.raw);
        if got.as_deref() != Some(r.version.as_str()) {
            return Err(format!(
                "{id}: the regex on the {} reply gives {got:?}, the lab recorded `{}`",
                r.service, r.version
            ));
        }
    }
    Ok(())
}

/// No entry's version regex or probe pattern may match another entry's recorded or real
/// example reply. Advisory-derived examples (`source_kind = "advisory"`) are left out: they
/// were never sent by a product, so only recorded replies count as the other side.
fn check_negative(entries: &BTreeMap<String, Table>, rec: &[Recorded]) -> Result<(), String> {
    let mut raws: Vec<(String, String)> =
        rec.iter().map(|r| (r.id.clone(), r.raw.clone())).collect();
    for (id, e) in entries {
        for ex in tables(table(e, "version", id)?, "examples", id)? {
            if ex.contains_key("source_kind") {
                continue;
            }
            raws.push((id.clone(), string(ex, "raw", id)?.to_string()));
        }
    }
    for (id, e) in entries {
        let mut patterns = vec![("version regex", version_regex(table(e, "version", id)?)?)];
        for p in tables(table(e, "recognize", id)?, "probes", id)? {
            if let Some(Value::String(m)) = p.get("match") {
                patterns.push(("probe pattern", Pattern::new(m)?));
            }
        }
        for (what, re) in &patterns {
            for (owner, raw) in &raws {
                if owner != id && re.matches(raw) {
                    return Err(format!(
                        "{id}: the {what} also matches {owner}'s reply `{raw}`"
                    ));
                }
            }
        }
    }
    Ok(())
}

/// (service name, catalog id, image repo) for every service in `lab/compose.yml`.
fn lab_services() -> Vec<(String, String, String)> {
    let docs = YamlLoader::load_from_str(&read(LAB_FILE)).unwrap();
    let services = docs[0]["services"].as_hash().expect("services");
    services
        .iter()
        .map(|(name, svc)| {
            (
                name.as_str().unwrap().to_string(),
                svc["labels"]["org.guard-dog.lab.id"]
                    .as_str()
                    .expect("lab id label")
                    .to_string(),
                normalise_image(svc["image"].as_str().expect("image")),
            )
        })
        .collect()
}

/// Each lab service's whole definition as text, for finding ports in it.
fn lab_texts() -> BTreeMap<String, String> {
    let docs = YamlLoader::load_from_str(&read(LAB_FILE)).unwrap();
    docs[0]["services"]
        .as_hash()
        .expect("services")
        .iter()
        .map(|(n, s)| (n.as_str().unwrap().to_string(), format!("{s:?}")))
        .collect()
}

fn check_lab(
    entries: &BTreeMap<String, Table>,
    lab: &[(String, String, String)],
) -> Result<(), String> {
    let services: BTreeSet<&str> = lab.iter().map(|(s, _, _)| s.as_str()).collect();
    let mapped: BTreeSet<&str> = LAB_SERVICES.iter().map(|(s, _)| *s).collect();
    if services != mapped {
        return Err(format!(
            "LAB_SERVICES {mapped:?} differs from the services in {LAB_FILE} {services:?}"
        ));
    }
    for (svc, id, repo) in lab {
        if lab_id(svc) != Some(id.as_str()) {
            return Err(format!(
                "lab service `{svc}` has label id `{id}`, LAB_SERVICES says {:?}",
                lab_id(svc)
            ));
        }
        let entry = entries
            .get(id)
            .ok_or(format!("lab service `{svc}` ({id}) has no catalog entry"))?;
        let images = strings(table(entry, "recognize", id)?, "images", id)?;
        let hit = images.iter().any(|p| match p.strip_suffix('*') {
            Some(prefix) => repo.starts_with(prefix),
            None => p == repo,
        });
        if !hit {
            return Err(format!(
                "{id}: lab image {repo} matches none of recognize.images {images:?}"
            ));
        }
    }
    Ok(())
}

/// A port whose source is the lab file must appear in that service's definition,
/// or as `<service>:<port>` in another lab service's.
fn check_lab_ports(
    entries: &BTreeMap<String, Table>,
    texts: &BTreeMap<String, String>,
) -> Result<(), String> {
    for (id, e) in entries {
        let Some(svc) = LAB_SERVICES.iter().find(|(_, i)| i == id).map(|(s, _)| *s) else {
            continue;
        };
        for p in tables(table(e, "recognize", id)?, "ports", id)? {
            if p.get("source").and_then(Value::as_str) != Some(LAB_FILE) {
                continue;
            }
            let port = p["port"].as_integer().unwrap();
            let own = Regex::new(&format!(r"[:=]{port}(?:[^0-9]|$)|(?:^|[^0-9]){port}:")).unwrap();
            let other = format!("{svc}:{port}");
            let found = texts.get(svc).is_some_and(|t| own.is_match(t))
                || texts.values().any(|t| t.contains(&other));
            if !found {
                return Err(format!(
                    "{id}: port {port} is not in {LAB_FILE} for `{svc}`"
                ));
            }
        }
    }
    Ok(())
}

type Product = (BTreeSet<String>, BTreeSet<String>);

fn judge_b_products() -> BTreeMap<String, Product> {
    let t: Table = toml::from_str(&read("fixtures/expected-matches.toml")).unwrap();
    let set = |x: &Table, k: &str| -> BTreeSet<String> {
        x[k].as_array()
            .unwrap()
            .iter()
            .map(|s| s.as_str().unwrap().to_string())
            .collect()
    };
    t["product"]
        .as_array()
        .unwrap()
        .iter()
        .map(|p| {
            let p = p.as_table().unwrap();
            (
                p["id"].as_str().unwrap().to_string(),
                (set(p, "aliases"), set(p, "packages")),
            )
        })
        .collect()
}

/// The link both ways: entries and Judge B's products agree, and the gap lists are exact.
fn check_products(
    entries: &BTreeMap<String, Table>,
    products: &BTreeMap<String, Product>,
    uncatalogued: &[&str],
    not_yet: &[&str],
) -> Result<(), String> {
    for id in CATALOGUED_BEFORE {
        if uncatalogued.contains(&id) {
            return Err(format!(
                "`{id}` is in CATALOGUED_BEFORE: it cannot go back into UNCATALOGUED"
            ));
        }
        if !entries.contains_key(id) {
            return Err(format!(
                "`{id}` is in CATALOGUED_BEFORE but its entry is gone"
            ));
        }
    }
    let extra: BTreeSet<&str> = entries
        .keys()
        .filter(|id| !products.contains_key(*id))
        .map(String::as_str)
        .collect();
    let not_yet_set: BTreeSet<&str> = not_yet.iter().copied().collect();
    if extra != not_yet_set {
        return Err(format!(
            "entries that are not Judge B products {extra:?} differ from NOT_YET_IN_JUDGE_B {not_yet_set:?}"
        ));
    }
    let gap: BTreeSet<&str> = products
        .keys()
        .filter(|id| !entries.contains_key(*id))
        .map(String::as_str)
        .collect();
    let listed: BTreeSet<&str> = uncatalogued.iter().copied().collect();
    if gap != listed {
        return Err(format!(
            "products with no entry {gap:?} differ from UNCATALOGUED {listed:?} (the list may only shrink, by editing it)"
        ));
    }
    for (id, (aliases, packages)) in products {
        let Some(e) = entries.get(id) else { continue };
        let got_aliases: BTreeSet<String> = strings(e, "aliases", id)?
            .into_iter()
            .map(String::from)
            .collect();
        let got_pkgs: BTreeSet<String> = strings(table(e, "advisories", id)?, "osv_packages", id)?
            .into_iter()
            .map(String::from)
            .collect();
        if &got_aliases != aliases {
            return Err(format!(
                "{id}: aliases differ from Judge B's: {got_aliases:?} vs {aliases:?}"
            ));
        }
        if &got_pkgs != packages {
            return Err(format!(
                "{id}: osv_packages differ from Judge B's: {got_pkgs:?} vs {packages:?}"
            ));
        }
    }
    Ok(())
}

// ---------- the tests ----------

#[test]
fn catalog_entries_are_valid() {
    let files = entry_files();
    assert!(
        files.len() >= 5,
        "the catalog holds at least the five lab services"
    );
    let all = entries(); // panics with the first broken entry
    all_loaded().unwrap(); // and the cross-entry rules: names, images, ports, links
    // The example in catalog/README.md must itself be a valid entry.
    let readme = read("catalog/README.md");
    let block = readme
        .split("```toml\n")
        .nth(1)
        .and_then(|s| s.split("```").next())
        .expect("README has a toml example");
    validate("strfry", block).unwrap();
    // Open questions are allowed, counted and printed, never guessed values.
    let todo: usize = all
        .values()
        .map(|e| e["review"]["todo"].as_array().unwrap().len())
        .sum();
    let advisory = all
        .values()
        .filter(|e| {
            e["version"]["examples"]
                .as_array()
                .unwrap()
                .iter()
                .all(|x| x.get("source_kind").is_some())
        })
        .count();
    println!(
        "{} entries, {todo} open todo items, {advisory} entries with only advisory-derived examples",
        all.len()
    );
}

#[test]
fn catalog_ids_and_aliases_are_unique() {
    // load_all refuses a name used twice; pin it on the real files and on a copy.
    all_loaded().unwrap();
    let cat = all_loaded().unwrap();
    let names: BTreeSet<&str> = cat
        .entries()
        .flat_map(|e| std::iter::once(e.id.as_str()).chain(e.aliases.iter().map(String::as_str)))
        .collect();
    let total: usize = cat.entries().map(|e| 1 + e.aliases.len()).sum();
    assert_eq!(names.len(), total);
}

#[test]
fn catalog_matches_judge_b_products() {
    check_products(
        &entries(),
        &judge_b_products(),
        &UNCATALOGUED,
        &NOT_YET_IN_JUDGE_B,
    )
    .unwrap();
}

#[test]
fn version_regexes_read_the_lab_recordings() {
    // Examples are checked inside validate; here the lab's own recorded replies are the data.
    let rec = recordings(&read("fixtures/lab-recorded/manifest.toml"));
    assert_eq!(rec.len(), 5, "the manifest records five services");
    check_recordings(&entries(), &rec).unwrap();
}

#[test]
fn version_regexes_do_not_match_other_services_replies() {
    let rec = recordings(&read("fixtures/lab-recorded/manifest.toml"));
    check_negative(&entries(), &rec).unwrap();
}

#[test]
fn version_regexes_read_other_forms_of_the_same_product() {
    // Forms with no recorded reply yet (the entries say so in `todo`). These are
    // written here, not recorded: they pin that the regexes are not too narrow
    // and that look-alikes (a fork, a modded build) are not read as the product.
    let all = entries();
    let core = version_regex(all["bitcoin-core"]["version"].as_table().unwrap()).unwrap();
    for (raw, want) in [
        ("/Satoshi:32.1.0/", Some("32.1")),
        ("/Satoshi:28.1.0/", Some("28.1")),
        ("/Satoshi:0.21.1/", Some("0.21.1")),
        ("/Satoshi:0.20.0/", Some("0.20.0")),
        ("/Satoshi:0.21.0rc1/", None),
        ("/Satoshi:28.1.0/Knots:20250305/", None),
        ("/Satoshi:28.1.0/Satoshi:1/", None),
    ] {
        assert_eq!(extract(&core, raw).as_deref(), want, "core {raw}");
    }
    let cln = version_regex(all["core-lightning"]["version"].as_table().unwrap()).unwrap();
    for (raw, want) in [
        ("v26.06.9", Some("26.06.9")),
        ("v24.11", Some("24.11")),
        ("v24.11.1", Some("24.11.1")),
        ("v24.11rc1", Some("24.11rc1")),
        ("v24.08.2-12-gabcdef0", Some("24.08.2-12-gabcdef0")),
        ("v24.11-modded", Some("24.11")),
    ] {
        assert_eq!(extract(&cln, raw).as_deref(), want, "cln {raw}");
    }
}

#[test]
fn every_lab_service_has_an_entry() {
    let lab = lab_services();
    assert_eq!(lab.len(), 5);
    check_lab(&entries(), &lab).unwrap();
}

#[test]
fn lab_ports_match_the_lab_file() {
    let all = entries();
    check_lab_ports(&all, &lab_texts()).unwrap();
    // The lab ports are really claimed: at least one entry cites the lab file.
    let cited = all
        .values()
        .flat_map(|e| {
            e["recognize"]
                .get("ports")
                .and_then(Value::as_array)
                .into_iter()
                .flatten()
        })
        .filter(|p| p.get("source").and_then(Value::as_str) == Some(LAB_FILE))
        .count();
    assert!(cited >= 6, "the lab ports are cited, found {cited}");
}

#[test]
fn catalog_images_and_ports_do_not_overlap() {
    // load_all refuses an overlapping image and any port shared outside SHARED_PORTS;
    // this also pins that every listed shared port really is shared.
    let cat = all_loaded().unwrap();
    let mut ports: BTreeMap<(u16, &str), BTreeSet<&str>> = BTreeMap::new();
    for e in cat.entries() {
        for p in &e.recognize.ports {
            ports
                .entry((p.port, p.proto.as_str()))
                .or_default()
                .insert(&e.id);
        }
    }
    let shared: BTreeSet<(u16, &str)> = ports
        .iter()
        .filter(|(_, ids)| ids.len() > 1)
        .map(|(k, _)| *k)
        .collect();
    let allowed: BTreeSet<(u16, &str)> = SHARED_PORTS.iter().map(|(p, pr, _)| (*p, *pr)).collect();
    assert_eq!(shared, allowed, "SHARED_PORTS must equal the shared ports");
}

#[test]
fn catalog_calls_are_read_only() {
    // validate() refuses a call outside READ_ONLY_CALLS; this also pins that every
    // listed call is used, so the list holds nothing that no entry needs.
    let mut used: BTreeSet<(String, String)> = BTreeSet::new();
    for e in all_loaded().unwrap().entries() {
        // image-label and platform-manifest sources make no call, so they use none.
        for (form, d) in e.call_descriptors() {
            used.insert((form.into(), d));
        }
    }
    let listed: BTreeSet<(String, String)> = READ_ONLY_CALLS
        .iter()
        .map(|(f, d)| (f.to_string(), d.to_string()))
        .collect();
    assert_eq!(
        used, listed,
        "READ_ONLY_CALLS must equal the calls the entries use"
    );
}

#[test]
fn urls_are_https_and_on_the_upstream() {
    // The loader checks every URL (see broken_entries_are_refused); this pins that
    // the real entries really hold URLs: every repo is https://github.com/owner/repo
    // style, and the feeds, policies and keys the loader accepted are all https.
    let cat = all_loaded().unwrap();
    for e in cat.entries() {
        assert!(e.upstream.repo.starts_with("https://"), "{}", e.id);
        let urls = e
            .upstream
            .security_policy
            .iter()
            .chain(&e.upstream.release_feed)
            .chain(&e.signing.keys_url)
            .chain(e.advisories.feeds.iter().map(|f| &f.url));
        for u in urls {
            assert!(u.starts_with("https://"), "{}: {u}", e.id);
        }
    }
}

#[test]
fn catalog_holds_no_secret_shapes() {
    // Already part of validate; run the scan on the raw files again so a
    // failure names this test, and prove the scan lets the allowed shapes by.
    for (stem, text) in entry_files() {
        catalog::scan_secret_shapes(&text).unwrap_or_else(|e| panic!("{stem}: {e}"));
    }
    catalog::scan_secret_shapes(
        "a = \"documentation address 192.0.2.7, 2001:db8::1 and 2001:db8:abcd::5; TLS 1.3 at 12:30:45\"\n[signing]\nkeys = [{ fingerprint = \"0123456789abcdef0123456789abcdef01234567\" }]",
    )
    .unwrap();
}

#[test]
fn probe_patterns_are_bounded() {
    let mut probes = 0;
    for e in all_loaded().unwrap().entries() {
        for p in &e.recognize.probes {
            if p.pattern().is_some() {
                probes += 1;
            }
        }
    }
    assert!(probes >= 2, "strfry and nutshell have probes with patterns");
    // A pattern too big for the limit, too long, with inline flags, or ending in an escaped $ is refused.
    assert!(Pattern::new(r"^(?:[a-z]{1,1000}){1,1000}$").is_err());
    assert!(Pattern::new(&format!("^{}$", "a".repeat(300))).is_err());
    assert!(Pattern::new(r"^(?m)(?P<version>\d+)$").is_err());
    assert!(Pattern::new(r"^(?s:.)$").is_err());
    assert!(Pattern::new(r"^a\$").is_err());
    assert!(Pattern::new(r"^a\\$").is_ok());
    // An alternation cannot match part of a reply: the pattern is wrapped in \A(?:...)\z.
    let alt = Pattern::new(r"^nomatch|(?P<version>\d+\.\d+)\.0/$").unwrap();
    assert_eq!(extract(&alt, "anything at all 99.9.0/"), None);
    assert_eq!(extract(&alt, "99.9.0/").as_deref(), Some("99.9"));
}

fn text_of(stem: &str) -> String {
    entry_files()
        .into_iter()
        .find(|(s, _)| s == stem)
        .unwrap()
        .1
}

fn refused(stem: &str, text: &str, expect: &str) {
    match validate(stem, text) {
        Ok(_) => panic!("a broken entry was accepted; expected an error with `{expect}`"),
        Err(e) => assert!(e.contains(expect), "wrong refusal: {e} (wanted `{expect}`)"),
    }
}

fn replaced(text: &str, from: &str, to: &str) -> String {
    assert!(text.contains(from), "mutation target `{from}` is gone");
    text.replacen(from, to, 1)
}

#[test]
fn broken_entries_are_refused() {
    let core = text_of("bitcoin-core");
    let fry = text_of("strfry");
    let lnd = text_of("lnd");
    let cln = text_of("core-lightning");
    let nut = text_of("nutshell");
    for (stem, text) in [
        ("bitcoin-core", &core),
        ("strfry", &fry),
        ("lnd", &lnd),
        ("core-lightning", &cln),
        ("nutshell", &nut),
    ] {
        validate(stem, text).unwrap();
    }
    let c = |from: &str, to: &str, want: &str| {
        refused("bitcoin-core", &replaced(&core, from, to), want);
    };
    let l = |from: &str, to: &str, want: &str| refused("lnd", &replaced(&lnd, from, to), want);
    let k = |from: &str, to: &str, want: &str| {
        refused("core-lightning", &replaced(&cln, from, to), want);
    };
    let f = |from: &str, to: &str, want: &str| refused("strfry", &replaced(&fry, from, to), want);
    let summary = "The reference Bitcoin full node and wallet.";
    let argv = "argv = [\"lightning-cli\", \"getinfo\"]";
    let regex = r"regex = '^/Satoshi:(?P<version>0\.\d+\.\d+|[1-9]\d*\.\d+)(?:\.0)?/$'";
    let cred = "credential = \"rpcauth user with rpcwhitelist=<user>:getnetworkinfo\"";
    let feed = "release_feed = \"https://github.com/bitcoin/bitcoin/releases.atom\"";

    // ids
    c("id = \"bitcoin-core\"", "id = \"Bitcoin_Core\"", "slug");
    refused("other-name", &core, "must equal the file name");

    // 1. calls only read: no shell, no interpreter, no absolute path, nothing outside READ_ONLY_CALLS
    k(
        argv,
        "argv = [\"/bin/sh\", \"-c\", \"reboot\"]",
        "bare program name",
    );
    k(
        argv,
        "argv = [\"sh\", \"-c\", \"reboot\"]",
        "shell or interpreter",
    );
    k(
        argv,
        "argv = [\"env\", \"lightning-cli\", \"getinfo\"]",
        "shell or interpreter",
    );
    k(
        argv,
        "argv = [\"python3\", \"-c\", \"x\"]",
        "shell or interpreter",
    );
    k(
        argv,
        "argv = [\"rm\", \"-rf\"]",
        "not in recognize.binaries",
    );
    k(
        argv,
        "argv = [\"lightning-cli\", \"getinfo; id\"]",
        "never shell",
    );
    k(argv, "argv = [\"lightning-cli\", \"$(id)\"]", "never shell");
    k(
        argv,
        "argv = [\"lightning-cli\", \"withdraw\", \"bcrt1qxyz\", \"all\"]",
        "READ_ONLY_CALLS",
    );
    k(
        argv,
        "argv = [\"lightning-cli\", \"--rpc-file=/tmp/x\", \"stop\"]",
        "READ_ONLY_CALLS",
    );
    k(
        argv,
        "argv = [\"lightning-cli\", \"getinfo\", \"--rpc-file=x\"]",
        "READ_ONLY_CALLS",
    );
    k(
        "run_as = \"service-user-in-container\"",
        "run_as = \"root\"",
        "run_as",
    );
    c(
        "method = \"getnetworkinfo\"",
        "method = \"stop\"",
        "READ_ONLY_CALLS",
    );
    c(
        "method = \"getnetworkinfo\"",
        "method = \"getnetworkinfo/../stop\"",
        "`..`",
    );
    l(
        "method = \"verrpc.Versioner/GetVersion\"",
        "method = \"lnrpc.Lightning/StopDaemon\"",
        "READ_ONLY_CALLS",
    );
    l(
        "method = \"verrpc.Versioner/GetVersion\"",
        "method = \"Versioner/GetVersion\"",
        "READ_ONLY_CALLS",
    );
    l(
        "method = \"lnrpc.State/GetState\"",
        "method = \"lnrpc.Lightning/StopDaemon\"",
        "READ_ONLY_CALLS",
    );
    refused(
        "strfry",
        &replaced(
            &fry,
            "path = \"/\"\naccept = \"application/nostr+json\"\nfield = \"version\"",
            "path = \"http://10.0.0.5/\"\nfield = \"version\"",
        ),
        "local path",
    );
    refused(
        "strfry",
        &replaced(
            &fry,
            "path = \"/\"\naccept = \"application/nostr+json\"\nfield = \"version\"",
            "path = \"/../x\"\nfield = \"version\"",
        ),
        "local path",
    );
    refused(
        "strfry",
        &replaced(
            &fry,
            "path = \"/\"\naccept = \"application/nostr+json\"\nfield = \"version\"",
            "path = \"/admin\"\nfield = \"version\"",
        ),
        "READ_ONLY_CALLS",
    );
    f(
        "[version.call]\nmethod = \"GET\"",
        "[version.call]\nmethod = \"POST\"",
        "GET",
    );
    c(
        cred,
        "credential = \"login at https://evil.example/\"",
        "must not name",
    );
    c(cred, "credential = \"user@evil.example\"", "must not name");
    c(
        cred,
        "credential = \"read the cloud metadata service\"",
        "must not name",
    );
    c(
        cred,
        "credential = \"abcdefghijklmnop.onion\"",
        "must not name",
    );
    // 4. the field read, TLS server name
    c(
        "field = \"subversion\"",
        "field = \"see https://evil.example/\"",
        "field must match",
    );
    c("field = \"subversion\"", "field = \"a..b\"", "`..`");
    l(
        "server_name = \"localhost\"",
        "server_name = \"evil.example\"",
        "must not name",
    );
    l(
        "server_name = \"localhost\"",
        "server_name = \"other\"",
        "localhost` or the entry id",
    );
    l(
        "server_name = \"localhost\"",
        "server_name = \"localhost\"\nskip_verify = true",
        "unknown key `skip_verify`",
    );
    refused(
        "lnd",
        &replaced(
            &lnd,
            "[version.tls]\ncert_source = \"node-tls-cert\"\nserver_name = \"localhost\"\n",
            "",
        ),
        "version.tls",
    );

    // 3. regexes: no `version` group, disagreeing, unanchored, too long, inline flags, alternation
    c("(?P<version>", "(?P<ver>", "named `version`");
    c(
        regex,
        r"regex = '^/Satoshi:(?P<version>\d+)\.\d+\.0/$'",
        "expected `32.1`",
    );
    c(
        regex,
        r"regex = '/Satoshi:(?P<version>0\.\d+\.\d+|[1-9]\d*\.\d+)(?:\.0)?/$'",
        "anchored",
    );
    c(
        regex,
        &format!(
            "regex = '^/Satoshi:(?P<version>\\d+\\.\\d+)\\.0/{}$'",
            "/?".repeat(120)
        ),
        "longer than",
    );
    c(
        regex,
        r"regex = '^(?m)/Satoshi:(?P<version>\d+\.\d+)\.0/$'",
        "inline flags",
    );
    c(
        regex,
        r"regex = '^nomatch|(?P<version>\d+\.\d+)\.0/$'",
        "expected `32.1`",
    );
    refused(
        "strfry",
        &replaced(&fry, "match = '^git", "match = 'git"),
        "anchored",
    );
    refused(
        "strfry",
        &replaced(&fry, "match = '^git", "match = '^(?i)git"),
        "inline flags",
    );
    // a stray `)` must not close the wrapper and free the rest of the pattern
    for bad in [r"^nomatch)|(?:(?P<version>\d+\.\d+)\.0/$", r"^x)|(?:.*$"] {
        assert!(
            Pattern::new(bad).unwrap_err().contains("on its own"),
            "{bad}"
        );
    }
    c(
        regex,
        r"regex = '^x)|(?:(?P<version>.*)$'",
        "compile on its own",
    );
    // the reply cap: a long reply is never matched
    let re = Pattern::new(r"^(?P<version>\d+)$").unwrap();
    assert_eq!(extract(&re, "7").as_deref(), Some("7"));
    assert_eq!(extract(&re, &"7".repeat(MAX_REPLY + 1)), None);

    // closed schema
    c(
        "format = 1\n",
        "format = 1\nsurprise = 1\n",
        "unknown key `surprise`",
    );
    c(
        "[review]\n",
        "[review]\nextra = true\n",
        "unknown key `extra`",
    );
    c("money = true\n", "", "missing key `money`");
    c(
        "licence = \"MIT\"\n",
        "licence = \"MIT\"\npurl = \"pkg:x/y\"\n",
        "unknown key `purl`",
    );

    // URLs
    c(
        "repo = \"https://github.com/bitcoin/bitcoin\"",
        "repo = \"http://github.com/bitcoin/bitcoin\"",
        "must be https",
    );
    c(
        "releases.atom\"",
        "releases.atom?token=1\"",
        "no credentials, query",
    );
    c(
        "https://bitcoincore.org/en/download/",
        "https://user@bitcoincore.org/en/download/",
        "no credentials, query",
    );
    c(
        feed,
        "release_feed = \"https://example.com/releases.atom\"",
        "not under upstream",
    );
    // owner/repo level, not host level
    c(
        feed,
        "release_feed = \"https://github.com/bitcoin/other/releases.atom\"",
        "not under upstream",
    );
    c(
        feed,
        "release_feed = \"https://github.com/bitcoin/bitcoin-evil/releases.atom\"",
        "not under upstream",
    );
    c(
        "  \"https://github.com/bitcoin-core/guix.sigs\",\n",
        "  \"https://github.com/bitcoin-core/guix.sigs/tree/main\",\n",
        "owner/repo",
    );
    // 2. websites and related repos cannot open a host
    c(
        "website = \"https://bitcoincore.org/\"",
        "website = \"https://github.com/\"",
        "shared code host",
    );
    c(
        "website = \"https://bitcoincore.org/\"",
        "website = \"https://github.com/bitcoin-core\"",
        "shared code host",
    );
    c(
        "website = \"https://bitcoincore.org/\"",
        "website = \"https://gitlab.com/evil\"",
        "shared code host",
    );
    c(
        "website = \"https://bitcoincore.org/\"",
        "website = \"https://metadata.google.internal/\"",
        "internal host",
    );
    c(
        "website = \"https://bitcoincore.org/\"",
        "website = \"https://printer.local/\"",
        "internal host",
    );
    c(
        "website = \"https://bitcoincore.org/\"",
        "website = \"https://192.168.1.5/\"",
        "internal host",
    );
    c(
        "https://github.com/bitcoin-core/guix.sigs\",\n",
        "https://gitlab.com/bitcoin-core/guix.sigs\",\n",
        "same code host",
    );
    // shared pages hosts: only the upstream owner's own subdomain; look-alike loopback names
    for site in [
        "https://evil.github.io/",
        "https://github.io/",
        "https://other.netlify.app/",
        "https://x.bitcoin.pages.dev/",
    ] {
        c(
            "website = \"https://bitcoincore.org/\"",
            &format!("website = \"{site}\""),
            "shared pages host",
        );
    }
    for site in [
        "https://app.localtest.me/",
        "https://10-0-0-1.nip.io/",
        "https://x.sslip.io/",
        "https://a.lvh.me/",
    ] {
        c(
            "website = \"https://bitcoincore.org/\"",
            &format!("website = \"{site}\""),
            "internal host",
        );
    }
    validate(
        "bitcoin-core",
        &replaced(
            &core,
            "website = \"https://bitcoincore.org/\"",
            "website = \"https://bitcoin.github.io/\"",
        ),
    )
    .unwrap();
    // an exception listed for another entry does not work here
    c(
        "feeds = [{ kind = \"markdown-repo\", url = \"https://github.com/bitcoin-core/bitcoincore.org\" }]",
        "feeds = [{ kind = \"atom\", url = \"https://security.lightning.engineering/feed.xml\" }]",
        "not under upstream",
    );
    // 6. example and port sources
    c(
        "source = \"fixtures/lab-recorded/manifest.toml\"",
        "source = \"fixtures/lab-recorded/missing.toml\"",
        "file in the repo",
    );
    c(
        "source = \"fixtures/lab-recorded/manifest.toml\"",
        "source = \"https://evil.example/reply\"",
        "not under upstream",
    );
    c(
        "source = \"fixtures/lab-recorded/manifest.toml\"",
        "source = \"https://github.com/bitcoin/other/reply\"",
        "not under upstream",
    );
    c(
        "source = \"fixtures/lab-recorded/manifest.toml\"",
        "source = \"../etc/passwd\"",
        "file in the repo",
    );
    c(
        "source = \"lab/compose.yml\"",
        "source = \"lab/missing.yml\"",
        "file in the repo",
    );

    // network sources name their port; probes name theirs
    refused(
        "strfry",
        &replaced(&fry, "endpoint_port = 7777\n", "endpoint_port = 9999\n"),
        "one of recognize.ports",
    );
    let no_port = replaced(&fry, "endpoint_port = 7777\n", "");
    let no_todo = replaced(
        &no_port,
        "ports: 7777 comes from the lab healthcheck; confirm it is the upstream default",
        "something else",
    );
    validate("strfry", &no_port).unwrap(); // allowed while a `ports:` todo is open
    refused("strfry", &no_todo, "endpoint_port is missing");
    f(
        "port = 7777\nfield = \"software\"",
        "port = 9999\nfield = \"software\"",
        "probes.port must be one of",
    );
    // 5. binaries and units: empty needs a todo
    refused(
        "nutshell",
        &replaced(
            &nut,
            "  \"binaries: the mint runs as python3 -m cashu.mint; no executable name is catalogued yet\",\n",
            "",
        ),
        "`binaries:` item",
    );
    refused(
        "nutshell",
        &replaced(
            &nut,
            "  \"units: RaspiBlitz and myNode systemd unit names\",\n",
            "",
        ),
        "`units:` item",
    );

    // 9. blind spot: no GHSA and no machine-readable feed needs one
    k("blind_spot = ", "note = ", "unknown key `note`");
    refused(
        "core-lightning",
        &cln.lines()
            .filter(|l| !l.starts_with("blind_spot"))
            .collect::<Vec<_>>()
            .join("\n"),
        "blind_spot",
    );
    refused(
        "nutshell",
        &nut.lines()
            .filter(|l| !l.starts_with("blind_spot"))
            .collect::<Vec<_>>()
            .join("\n"),
        "blind_spot",
    );
    validate(
        "bitcoin-core",
        &replaced(
            &core,
            "ghsa = false\n",
            "ghsa = false\nblind_spot = \"Some fixes ship only in release notes.\"\n",
        ),
    )
    .unwrap();
    // 12. signed-multi needs min_signatures or a todo
    c(
        "  \"signing.min_signatures: how many Guix attestations make a release trustworthy\",\n",
        "",
        "min_signatures",
    );

    // secret shapes: an nsec (made up for this test), an onion, a public IP, a 40-hex outside the key list,
    // IPv6 forms, a base64 macaroon, and token prefixes
    let nsec = format!("nsec1{}", "q".repeat(58));
    c(summary, &nsec, "nsec");
    c(summary, "see abcdefghijklmnop.onion", "onion");
    c(summary, "node at 8.8.8.8", "IPv4");
    c(summary, "node at 2a01:4f8::1", "IPv6");
    c(summary, "node at fe80::1", "IPv6");
    c(summary, "node at 2a01:4f8:1:2:3:4:5:6", "IPv6");
    c(
        summary,
        "0123456789abcdef0123456789abcdef01234567",
        "40-hex",
    );
    c(
        summary,
        "AgEDbG5kAvgBAwoQ7Tq4CjCr0hb9PAQRiXEb1hIBMBoWCgdhZGRyZXNzEgRyZWFkEgV3cml0ZRoTCgRpbmZv",
        "base64 macaroon",
    );
    c(
        summary,
        &format!("ghp_{}", "a1B2".repeat(10)),
        "GitHub token",
    );
    c(summary, "AKIAABCDEFGHIJKLMNOP", "AWS access key");
    c(summary, &format!("sk-{}", "abcd1234".repeat(4)), "API key");
    c(
        summary,
        "one two three four five six seven eight nine ten eleven twelve",
        "seed-phrase",
    );
    // image names: a tag, a digest, a wildcard in the middle
    c(
        "images = [\"docker.io/bitcoin/bitcoin\"]",
        "images = [\"docker.io/bitcoin/bitcoin:latest\"]",
        "normalised",
    );
    c(
        "images = [\"docker.io/bitcoin/bitcoin\"]",
        "images = [\"bitcoin/bitcoin\"]",
        "normalised",
    );
    c(
        "images = [\"docker.io/bitcoin/bitcoin\"]",
        "images = [\"docker.io/*/bitcoin\"]",
        "normalised",
    );
    validate(
        "bitcoin-core",
        &replaced(
            &core,
            "images = [\"docker.io/bitcoin/bitcoin\"]",
            "images = [\"localhost:5000/bitcoin/bitcoin\", \"docker.io/bitcoin/bitcoin\"]",
        ),
    )
    .unwrap();

    advisory_examples_are_refused_when_unbacked();
}

/// Advisory-derived examples (`source_kind = "advisory"`, entries not yet recorded).
fn advisory_examples_are_refused_when_unbacked() {
    let alby = text_of("alby-hub");
    let btcpay = text_of("btcpay-server");
    validate("alby-hub", &alby).unwrap();
    validate("btcpay-server", &btcpay).unwrap();
    let file = "advisories/corpus/x_alby-hub-2026-09-internet-exposed-takeover.json";
    let a =
        |from: &str, to: &str, want: &str| refused("alby-hub", &replaced(&alby, from, to), want);
    let source = format!("source = \"{file}\"\nsource_kind");
    // No source file: it does not exist, it is missing, or it is a page instead of an advisory file.
    a(
        &source,
        "source = \"advisories/corpus/no-such-advisory.json\"\nsource_kind",
        "version.examples.source",
    );
    a(&source, "source_kind", "source");
    a(
        &source,
        "source = \"https://github.com/getAlby/hub\"\nsource_kind",
        "advisory file in the repo",
    );
    a(
        &source,
        "source = \"README.md\"\nsource_kind",
        "advisory file in the repo",
    );
    // The version is not in the advisory, or the example is not the bare value.
    a(
        "raw = \"1.19.0\"\nversion = \"1.19.0\"",
        "raw = \"1.99.0\"\nversion = \"1.99.0\"",
        "is not an introduced, fixed or last-affected",
    );
    // Another product's advisory (umbrelOS's), a page outside the corpus (the vendored schema).
    a(
        &format!("raw = \"1.19.0\"\nversion = \"1.19.0\"\nsource = \"{file}\""),
        "raw = \"1.2.2\"\nversion = \"1.2.2\"\nsource = \"advisories/corpus/CVE-2024-49379.json\"",
        "is not an introduced, fixed or last-affected",
    );
    a(
        &source,
        "source = \"advisories/schema/osv-schema-1.9.2.json\"\nsource_kind",
        "advisory file in the repo",
    );
    a(
        "raw = \"1.19.0\"\nversion = \"1.19.0\"",
        "raw = \"v1.19.0\"\nversion = \"1.19.0\"",
        "bare value",
    );
    // An unknown kind; and no `recorded-reply` todo.
    a(
        "source_kind = \"advisory\"",
        "source_kind = \"recorded\"",
        "source_kind",
    );
    a("  \"recorded-reply:", "  \"examples:", "recorded-reply");
    // A regex that reads plain versions of many majors is refused, however it is spelled.
    let re_line = "regex = '^(?P<version>1\\.\\d+\\.\\d+)$'";
    for bare in [
        "'^(?P<version>\\d+\\.\\d+\\.\\d+)$'",
        "'^(?P<version>[0-9]+\\.[0-9]+\\.[0-9]+)$'",
        "'^(?P<version>(?:\\d+\\.){2}\\d+)$'",
    ] {
        a(re_line, &format!("regex = {bare}"), "more than one major");
    }
    // P4: a regex that reads two majors with a character class is refused too.
    a(
        re_line,
        "regex = '^(?P<version>(?:[0-8]|[1-9]\\d)\\.\\d+\\.\\d+)$'",
        "more than one major",
    );
    // P9: a prefix on the regex, a "real" example with that prefix and an image do not get round it.
    refused(
        "alby-hub",
        &replaced(
            &replaced(
                &replaced(
                    &replaced(
                        &alby,
                        re_line,
                        "regex = '^x?(?P<version>\\d+\\.\\d+\\.\\d+)$'",
                    ),
                    "raw = \"1.19.0\"",
                    "raw = \"x1.19.0\"",
                ),
                "source_kind = \"advisory\"\n",
                "",
            ),
            "images = []",
            "images = [\"docker.io/getalby/hub\"]",
        ),
        "more than one major",
    );
    // An exception that is not needed any more is refused.
    refused(
        "strfry",
        &replaced(
            &text_of("strfry"),
            "regex = '^(?P<version>\\d+\\.\\d+\\.\\d+(?:-\\d+-g[0-9a-f]{7,})?)$'",
            "regex = '^(?P<version>1\\.\\d+\\.\\d+(?:-\\d+-g[0-9a-f]{7,})?)$'",
        ),
        "no longer reads many majors",
    );
    refused(
        "btcpay-server",
        &replaced(
            &btcpay,
            "regex = '^(?P<version>2\\.\\d+\\.\\d+)$'",
            "regex = '^(?P<version>\\d+\\.\\d+\\.\\d+)$'",
        ),
        "more than one major",
    );
    // With only advisory-derived examples there is nothing recorded to recognise it by:
    // no images, no ports, no probes.
    a(
        "images = []",
        "images = [\"docker.io/getalby/hub\"]",
        "no images, probes or ports yet",
    );
    a(
        "[version]",
        "[[recognize.ports]]\nport = 8080\nproto = \"tcp\"\nwhat = \"management web interface\"\nexposure = \"never-public\"\n\n[version]",
        "no images, probes or ports yet",
    );
    a(
        "[version]",
        "[[recognize.probes]]\nkind = \"http\"\nmethod = \"GET\"\npath = \"/\"\n\n[version]",
        "no images, probes or ports yet",
    );
}

#[test]
fn broken_cross_checks_are_refused() {
    let good = entries();
    let products = judge_b_products();
    let rec = recordings(&read("fixtures/lab-recorded/manifest.toml"));
    let lab = lab_services();
    check_recordings(&good, &rec).unwrap();
    check_negative(&good, &rec).unwrap();
    check_lab(&good, &lab).unwrap();
    check_lab_ports(&good, &lab_texts()).unwrap();
    check_products(&good, &products, &UNCATALOGUED, &NOT_YET_IN_JUDGE_B).unwrap();

    // A regex that turns the recorded Core reply into 32 instead of 32.1.
    let mut bad = good.clone();
    let v = bad
        .get_mut("bitcoin-core")
        .unwrap()
        .get_mut("version")
        .unwrap();
    v.as_table_mut().unwrap().insert(
        "regex".into(),
        Value::String(r"^/Satoshi:(?P<version>\d+)\.\d+\.0/$".into()),
    );
    assert!(
        check_recordings(&bad, &rec)
            .unwrap_err()
            .contains("the lab recorded `32.1`")
    );

    // A recorded version the entry's regex cannot give.
    let mut wrong = recordings(&read("fixtures/lab-recorded/manifest.toml"));
    wrong[0].version.push_str(".9");
    assert!(check_recordings(&good, &wrong).is_err());

    // A recorded line with no mapped lab service, a wrong mapping, and a lab service with no recording.
    let mut unmapped = recordings(&read("fixtures/lab-recorded/manifest.toml"));
    unmapped[0].service = "mystery".into();
    assert!(check_recordings(&good, &unmapped).is_err());
    let mut remapped = recordings(&read("fixtures/lab-recorded/manifest.toml"));
    remapped[0].id = "lnd".into();
    assert!(
        check_recordings(&good, &remapped)
            .unwrap_err()
            .contains("LAB_SERVICES says")
    );
    assert!(
        check_recordings(&good, &rec[1..])
            .unwrap_err()
            .contains("no recorded reply")
    );

    // A recorded service whose entry is missing.
    let mut missing = good.clone();
    missing.remove("strfry");
    assert!(
        check_recordings(&missing, &rec)
            .unwrap_err()
            .contains("no catalog entry")
    );
    assert!(
        check_lab(&missing, &lab)
            .unwrap_err()
            .contains("has no catalog entry")
    );

    // A version regex, or a probe pattern, wide enough to read another service's reply.
    let mut wide = good.clone();
    wide.get_mut("lnd")
        .unwrap()
        .get_mut("version")
        .unwrap()
        .as_table_mut()
        .unwrap()
        .insert("regex".into(), Value::String(r"^(?P<version>.+)$".into()));
    assert!(
        check_negative(&wide, &rec)
            .unwrap_err()
            .contains("version regex also matches")
    );
    let mut wide_probe = good.clone();
    let probes = wide_probe
        .get_mut("nutshell")
        .unwrap()
        .get_mut("recognize")
        .unwrap()
        .get_mut("probes")
        .unwrap()
        .as_array_mut()
        .unwrap();
    probes[0]
        .as_table_mut()
        .unwrap()
        .insert("match".into(), Value::String(r"^.+$".into()));
    assert!(
        check_negative(&wide_probe, &rec)
            .unwrap_err()
            .contains("probe pattern also matches")
    );

    // The negative check runs on recorded replies: an advisory-derived example is skipped
    // (fedimintd's pattern reads rtl's `0.15.12`), but the same reply, once it is not marked
    // as advisory-derived, is a real reply and is refused.
    check_negative(&good, &rec).unwrap();
    let mut unmarked = good.clone();
    let examples = unmarked
        .get_mut("rtl")
        .unwrap()
        .get_mut("version")
        .unwrap()
        .get_mut("examples")
        .unwrap()
        .as_array_mut()
        .unwrap();
    examples[0].as_table_mut().unwrap().remove("source_kind");
    assert!(
        check_negative(&unmarked, &rec)
            .unwrap_err()
            .contains("also matches rtl's reply")
    );

    // An image no recognize.images pattern covers, and a lab service the map does not know.
    let mut other_image = lab.clone();
    other_image[0].2 = "docker.io/someone/else".into();
    assert!(
        check_lab(&good, &other_image)
            .unwrap_err()
            .contains("matches none")
    );
    let mut extra_service = lab.clone();
    extra_service.push(("newcomer".into(), "lnd".into(), "docker.io/x/y".into()));
    assert!(
        check_lab(&good, &extra_service)
            .unwrap_err()
            .contains("differs from the services")
    );

    // A port the entry takes from the lab file that the lab file does not have.
    let mut port = good.clone();
    port.get_mut("strfry")
        .unwrap()
        .get_mut("recognize")
        .unwrap()
        .get_mut("ports")
        .unwrap()
        .as_array_mut()
        .unwrap()[0]
        .as_table_mut()
        .unwrap()
        .insert("port".into(), Value::Integer(9999));
    assert!(
        check_lab_ports(&port, &lab_texts())
            .unwrap_err()
            .contains("lab/compose.yml")
    );

    // The one image normaliser.
    assert_eq!(
        normalise_image("bitcoin/bitcoin@sha256:00"),
        "docker.io/bitcoin/bitcoin"
    );
    assert_eq!(normalise_image("ubuntu:24.04"), "docker.io/library/ubuntu");
    assert_eq!(normalise_image("Docker.io/Foo/Bar:1"), "docker.io/foo/bar");
    assert_eq!(
        normalise_image("index.docker.io/foo/bar"),
        "docker.io/foo/bar"
    );
    assert_eq!(
        normalise_image("ghcr.io/hoytech/strfry@sha256:00"),
        "ghcr.io/hoytech/strfry"
    );
    assert_eq!(
        normalise_image("localhost:5000/a/b:t"),
        "localhost:5000/a/b"
    );
    assert_eq!(
        normalise_image("registry.example:5000/a/b"),
        "registry.example:5000/a/b"
    );
    assert_eq!(normalise_image("docker.io/foo/*"), "docker.io/foo/*");

    // Aliases and packages that differ from Judge B's.
    let check =
        |m: &BTreeMap<String, Table>, u: &[&str], n: &[&str]| check_products(m, &products, u, n);
    let mut alias = good.clone();
    alias
        .get_mut("nutshell")
        .unwrap()
        .insert("aliases".into(), Value::Array(vec![]));
    assert!(
        check(&alias, &UNCATALOGUED, &[])
            .unwrap_err()
            .contains("aliases differ")
    );
    let mut pkg = good.clone();
    pkg.get_mut("lnd")
        .unwrap()
        .get_mut("advisories")
        .unwrap()
        .as_table_mut()
        .unwrap()
        .insert(
            "osv_packages".into(),
            Value::Array(vec![Value::String("Go example.com/lnd".into())]),
        );
    assert!(
        check(&pkg, &UNCATALOGUED, &[])
            .unwrap_err()
            .contains("osv_packages differ")
    );

    // The gap lists are exact, and the baseline cannot go back: too long, too short, a catalogued id
    // listed again, a baseline entry removed, and an entry that is not a product.
    let mut longer: Vec<&str> = UNCATALOGUED.to_vec();
    longer.push("zzz-unknown");
    assert!(
        check(&good, &longer, &[])
            .unwrap_err()
            .contains("may only shrink")
    );
    assert!(
        check(&good, &UNCATALOGUED[1..], &[])
            .unwrap_err()
            .contains("may only shrink")
    );
    let mut back: Vec<&str> = UNCATALOGUED.to_vec();
    back.push("lnd");
    assert!(
        check(&good, &back, &[])
            .unwrap_err()
            .contains("CATALOGUED_BEFORE")
    );
    assert!(
        check(&missing, &UNCATALOGUED, &[])
            .unwrap_err()
            .contains("CATALOGUED_BEFORE")
    );
    let mut stray = good.clone();
    let copy = stray["lnd"].clone();
    stray.insert("not-a-product".into(), copy);
    assert!(
        check(&stray, &UNCATALOGUED, &[])
            .unwrap_err()
            .contains("NOT_YET_IN_JUDGE_B")
    );
    check(&stray, &UNCATALOGUED, &["not-a-product"]).unwrap();
    assert!(
        check(&good, &UNCATALOGUED, &["not-a-product"])
            .unwrap_err()
            .contains("NOT_YET_IN_JUDGE_B")
    );
}

// ---------- the loader: the whole catalog ----------

/// Every real entry as (stem, text), borrowed.
fn pairs(files: &[(String, String)]) -> Vec<(&str, &str)> {
    files
        .iter()
        .map(|(s, t)| (s.as_str(), t.as_str()))
        .collect()
}

fn all_loaded() -> Result<Catalog, catalog::CatalogError> {
    catalog::load_all(&pairs(&entry_files()))
}

/// The real catalog with one entry's text replaced.
fn load_changed(stem: &str, from: &str, to: &str) -> Result<Catalog, catalog::CatalogError> {
    let mut files = entry_files();
    let f = files.iter_mut().find(|(s, _)| s == stem).unwrap();
    f.1 = replaced(&f.1, from, to);
    catalog::load_all(&pairs(&files))
}

fn load_refused(stem: &str, from: &str, to: &str, want: &str) {
    match load_changed(stem, from, to) {
        Ok(_) => panic!("a broken catalog was accepted; expected an error with `{want}`"),
        Err(e) => assert!(
            e.to_string().contains(want),
            "wrong refusal: {e} (wanted `{want}`)"
        ),
    }
}

#[test]
fn broken_catalogs_are_refused() {
    all_loaded().unwrap();
    // Images shared between entries: the same one, and one a wildcard covers.
    load_refused(
        "strfry",
        "images = [\"ghcr.io/hoytech/strfry\"]",
        "images = [\"docker.io/lightninglabs/lnd\"]",
        "overlap",
    );
    load_refused(
        "strfry",
        "images = [\"ghcr.io/hoytech/strfry\"]",
        "images = [\"docker.io/lightninglabs/*\"]",
        "overlap",
    );
    // A port shared outside SHARED_PORTS (lnd's gRPC port).
    load_refused(
        "strfry",
        "[version]",
        "[[recognize.ports]]\nport = 10009\nproto = \"tcp\"\nwhat = \"x\"\nexposure = \"lan\"\n\n[version]",
        "SHARED_PORTS",
    );
    // A name used twice: an alias that is another entry's id.
    load_refused(
        "lnd",
        "aliases = []",
        "aliases = [\"strfry\"]",
        "used by both",
    );
    // fork_of and bundles: a missing target, a self-reference, a cycle.
    load_refused(
        "lnd",
        "licence = \"MIT\"\n",
        "licence = \"MIT\"\nfork_of = \"nope\"\n",
        "not an entry",
    );
    load_refused(
        "lnd",
        "licence = \"MIT\"\n",
        "licence = \"MIT\"\nbundles = [\"lnd\"]\n",
        "itself",
    );
    let mut files = entry_files();
    for (stem, from, to) in [
        (
            "lnd",
            "licence = \"MIT\"\n",
            "licence = \"MIT\"\nbundles = [\"strfry\"]\n",
        ),
        (
            "strfry",
            "licence = \"GPL-3.0\"\n",
            "licence = \"GPL-3.0\"\nfork_of = \"lnd\"\n",
        ),
    ] {
        let f = files.iter_mut().find(|(s, _)| s == stem).unwrap();
        f.1 = replaced(&f.1, from, to);
    }
    let err = catalog::load_all(&pairs(&files)).unwrap_err();
    assert!(err.to_string().contains("cycle"), "{err}");
    // The same file twice.
    let lnd = text_of("lnd");
    let err = catalog::load_all(&[("lnd", &lnd), ("lnd", &lnd)]).unwrap_err();
    assert!(err.to_string().contains("listed twice"), "{err}");
    // A broken entry anywhere fails the whole catalog, naming the entry.
    let err = load_changed("lnd", "id = \"lnd\"", "id = \"Bad_Id\"").unwrap_err();
    assert!(err.to_string().starts_with("lnd: "), "{err}");
}

// ---------- the embedded catalog ----------

#[test]
fn embedded_catalog_loads_every_entry() {
    let cat = catalog::embedded().unwrap();
    assert_eq!(cat.len(), entry_files().len());
    assert!(!cat.is_empty());
    for (stem, _) in entry_files() {
        let e = cat
            .get(&stem)
            .unwrap_or_else(|| panic!("{stem} not embedded"));
        assert_eq!(e.id, stem);
        assert!(!e.display_name().is_empty());
        assert!(!e.osv_packages().is_empty(), "{stem}");
    }
    // Sorted by id.
    let ids: Vec<&str> = cat.entries().map(|e| e.id.as_str()).collect();
    let mut sorted = ids.clone();
    sorted.sort_unstable();
    assert_eq!(ids, sorted);
}

#[test]
fn embedded_file_list_is_exactly_the_catalog_folder() {
    // No missing entry, no extra one, same text, and the list itself is sorted.
    let on_disk = entry_files();
    let listed = catalog::embedded_files();
    let names: Vec<&str> = listed.iter().map(|(n, _)| *n).collect();
    let disk_names: Vec<&str> = on_disk.iter().map(|(n, _)| n.as_str()).collect();
    assert_eq!(names, disk_names, "catalog_files.rs differs from catalog/");
    for ((n, text), (_, disk)) in listed.iter().zip(&on_disk) {
        assert_eq!(text, disk, "{n}: the embedded text is stale");
    }
}

#[test]
fn entries_on_port_finds_entries_sorted_by_id() {
    let cat = catalog::embedded().unwrap();
    // The Lightning peer port: shared, reviewed, and sorted.
    let ids: Vec<&str> = cat
        .entries_on_port(9735)
        .iter()
        .map(|e| e.id.as_str())
        .collect();
    assert!(ids.len() >= 2, "{ids:?}");
    assert!(
        ids.contains(&"lnd") && ids.contains(&"core-lightning"),
        "{ids:?}"
    );
    let mut sorted = ids.clone();
    sorted.sort_unstable();
    assert_eq!(ids, sorted);
    // One owner, and none.
    let relay: Vec<&str> = cat
        .entries_on_port(7777)
        .iter()
        .map(|e| e.id.as_str())
        .collect();
    assert_eq!(relay, ["strfry"]);
    assert!(cat.entries_on_port(1).is_empty());
    assert!(cat.entries_on_port(65535).is_empty());
}

#[test]
fn match_version_refuses_long_replies_and_partial_matches() {
    let cat = catalog::embedded().unwrap();
    let core = cat.get("bitcoin-core").unwrap();
    assert_eq!(core.match_version("/Satoshi:32.1.0/"), Some("32.1"));
    // Anchored: junk before or after is not a match, nor is a second product.
    assert_eq!(core.match_version("x/Satoshi:32.1.0/"), None);
    assert_eq!(core.match_version("/Satoshi:32.1.0/ "), None);
    assert_eq!(core.match_version("/Satoshi:28.1.0/Knots:20250305/"), None);
    // The reply cap: 256 bytes are read, 257 never are, whatever the pattern says.
    let fry = cat.get("strfry").unwrap();
    assert_eq!(fry.match_version("1.1.2"), Some("1.1.2"));
    let pat = Pattern::new(r"^(?P<version>\d+)$").unwrap();
    assert_eq!(
        pat.version(&"7".repeat(MAX_REPLY)).map(str::len),
        Some(MAX_REPLY)
    );
    assert_eq!(pat.version(&"7".repeat(MAX_REPLY + 1)), None);
    assert!(!pat.matches(&"7".repeat(MAX_REPLY + 1)));
    // An alternation cannot match part of a reply (the \A(?:...)\z wrapper).
    let alt = Pattern::new(r"^nomatch|(?P<version>\d+)\.0$").unwrap();
    assert_eq!(alt.version("junk 9.0"), None);
    assert_eq!(alt.version("9.0"), Some("9"));
    // No reply of any real entry's pattern is read when it is 257 bytes long.
    for e in cat.entries() {
        let long = format!("{}{}", "1".repeat(MAX_REPLY), ".0.0");
        assert_eq!(e.match_version(&long), None, "{}", e.id);
    }
}

#[test]
fn version_call_exposes_what_the_scanner_needs() {
    let cat = catalog::embedded().unwrap();
    let lnd = cat.get("lnd").unwrap();
    let v = lnd.version_call();
    assert_eq!(v.source, catalog::Source::Grpc);
    assert_eq!(v.endpoint_port, Some(10009));
    assert_eq!(v.call.field, "version");
    assert_eq!(
        v.call.call,
        Some(catalog::Call::Grpc {
            method: "verrpc.Versioner/GetVersion".into()
        })
    );
    assert_eq!(v.tls.as_ref().unwrap().server_name, "localhost");
    assert_eq!(lnd.scheme(), catalog::Scheme::SemverBeta);
    assert_eq!(lnd.display_name(), "LND");
    let fry = cat.get("strfry").unwrap().version_call();
    assert_eq!(
        fry.call.call,
        Some(catalog::Call::Http {
            path: "/".into(),
            accept: Some("application/nostr+json".into())
        })
    );
}

/// A minimal valid entry that lists the Lightning peer port, for the per-port cap.
fn synthetic(id: &str) -> String {
    format!(
        r#"format = 1
id = "{id}"
name = "Synthetic"
kind = "service"
aliases = []
summary = "A made-up product for a test."
money = false
licence = "MIT"

[upstream]
repo = "https://github.com/o/{id}"

[recognize]
images = ["docker.io/o/{id}"]
binaries = []
units = []

[[recognize.ports]]
port = 9735
proto = "tcp"
what = "peer"
exposure = "lan"

[version]
source = "image-label"
credential = "none"
regex = '^(?P<version>2\.\d+\.\d+)$'
scheme = "semver"

[version.call]
field = "version"

[[version.examples]]
raw = "2.1.0"
version = "2.1.0"
source = "https://github.com/o/{id}"

[advisories]
osv_packages = ["GIT https://github.com/o/{id}"]
ghsa = false
feeds = []
blind_spot = "None."

[signing]
level = "unknown"

[review]
last_reviewed = 2026-11-17
sources = ["https://github.com/o/{id}"]
todo = ["binaries: none", "units: none"]
"#
    )
}

#[test]
fn a_port_in_too_many_entries_is_refused() {
    // The cap equals the fact model's MAX_CANDIDATES.
    assert_eq!(catalog::CATALOG_MAX_PRODUCTS_PER_PORT, 32);
    let build = |n: usize| -> Result<Catalog, catalog::CatalogError> {
        let texts: Vec<(String, String)> = (0..n)
            .map(|i| {
                let id = format!("svc-{i}");
                let text = synthetic(&id);
                (id, text)
            })
            .collect();
        catalog::load_all(&pairs(&texts))
    };
    build(32).unwrap();
    let err = build(33).unwrap_err();
    assert!(
        err.to_string().contains("CATALOG_MAX_PRODUCTS_PER_PORT"),
        "{err}"
    );
}
