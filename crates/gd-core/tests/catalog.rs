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

use gd_core::Untrusted;
use gd_core::catalog::{
    self, Catalog, EndpointKey, Entry, Identified, IdentifiedBy, MAX_REPLY, OTHER_URLS, Pattern,
    READ_ONLY_CALLS, RELATED_OTHER_OWNER, ReplyMatch, SHARED_PORTS, Unreadable, VersionMatch,
    normalise_image,
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

/// Every regular file under `fixtures/`, `advisories/` and `lab/`, as a path
/// relative to the repo root with `/` separators. Found with `symlink_metadata`,
/// so a symlink is never followed and is not in the list: a citation cannot
/// reach outside the repo through one.
fn inventory() -> BTreeSet<String> {
    let mut out = BTreeSet::new();
    for top in ["fixtures", "advisories", "lab"] {
        walk_files(&root().join(top), top, &mut out);
    }
    out
}

/// The regular files below `dir` (symlinks skipped, never followed), as `rel/...` paths.
fn walk_files(dir: &Path, rel: &str, out: &mut BTreeSet<String>) {
    let Ok(items) = fs::read_dir(dir) else { return };
    for item in items.flatten() {
        let name = item.file_name().to_string_lossy().into_owned();
        let path = item.path();
        let rel = format!("{rel}/{name}");
        let Ok(meta) = fs::symlink_metadata(&path) else {
            continue;
        };
        if meta.file_type().is_symlink() {
            continue;
        }
        if meta.is_dir() {
            walk_files(&path, &rel, out);
        } else if meta.is_file() {
            out.insert(rel);
        }
    }
}

/// A `source` is a URL (the loader checked it is under the upstream and that a
/// file name has no `..`) or a file in the trusted inventory, still inside the
/// repo root once canonicalised. A failure names the field and the item's
/// index only: the cited text is never used as a path or shown.
fn source_exists(
    inv: &BTreeSet<String>,
    field: &str,
    index: usize,
    src: &str,
) -> Result<(), String> {
    if src.starts_with("https://") {
        return Ok(());
    }
    let bad =
        || format!("{field} (item {index}) must be a file in the repo or a URL under the upstream");
    if !inv.contains(src) {
        return Err(bad());
    }
    let root = fs::canonicalize(root()).map_err(|_| bad())?;
    let real = fs::canonicalize(root.join(src)).map_err(|_| bad())?;
    if real.starts_with(&root) && real.is_file() {
        Ok(())
    } else {
        Err(bad())
    }
}

/// The checks that read files: every port and example source exists, and an
/// advisory example's version is in that advisory.
fn check_files(e: &Entry) -> Result<(), String> {
    let inv = inventory();
    for (i, p) in e.recognize().ports.iter().enumerate() {
        if let Some(s) = &p.source {
            source_exists(&inv, "recognize.ports.source", i, s)?;
        }
    }
    for (i, ex) in e.version_call().examples().iter().enumerate() {
        source_exists(&inv, "version.examples.source", i, &ex.source)?;
        if ex.advisory {
            advisory_has_version(&ex.source, &ex.version, &e.advisories().osv_packages)?;
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
    re.version(&u(raw)).read().map(str::to_string)
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
                if owner != id && re.matches(&u(raw)).is_read() {
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
        // Tool services (probe, scanner) have a compose profile and are not lab products.
        .filter(|(_, svc)| svc["profiles"].is_badvalue())
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
        .filter(|(_, s)| s["profiles"].is_badvalue())
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
        .flat_map(|e| std::iter::once(e.id()).chain(e.aliases().iter().map(String::as_str)))
        .collect();
    let total: usize = cat.entries().map(|e| 1 + e.aliases().len()).sum();
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
        // Modded builds keep their marker so the scheme can refuse them.
        ("v24.11-modded", Some("24.11-modded")),
        (
            "v24.08.2-12-gabcdef0-modded",
            Some("24.08.2-12-gabcdef0-modded"),
        ),
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
        for p in &e.recognize().ports {
            ports
                .entry((p.port, p.proto.as_str()))
                .or_default()
                .insert(e.id());
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
        assert!(e.upstream().repo.starts_with("https://"), "{}", e.id());
        let urls = e
            .upstream()
            .security_policy
            .iter()
            .chain(&e.upstream().release_feed)
            .chain(&e.signing().keys_url)
            .chain(e.advisories().feeds.iter().map(|f| &f.url));
        for u in urls {
            assert!(u.starts_with("https://"), "{}: {u}", e.id());
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
        for p in &e.recognize().probes {
            // Every probe has a pattern (a patternless probe is refused at load).
            let _ = p.pattern();
            probes += 1;
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
            "path = \"http://printer/\"\nfield = \"version\"",
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
        "secret shape: onion",
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
        "an unknown key",
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
        "version.examples[0].raw",
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
        "version.examples[0].raw",
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
        "an unknown key",
    );
    c("[review]\n", "[review]\nextra = true\n", "an unknown key");
    c("money = true\n", "", "missing key `money`");
    c(
        "licence = \"MIT\"\n",
        "licence = \"MIT\"\npurl = \"pkg:x/y\"\n",
        "an unknown key",
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
        "website = \"https://127.1/\"",
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
    // With no endpoint_port the probe has no port either (the identity rule counts a
    // probe on the endpoint port, or on no port).
    let no_port = replaced(
        &replaced(&fry, "endpoint_port = 7777\n", ""),
        "port = 7777\nfield = \"software\"",
        "field = \"software\"",
    );
    // The same without the probe at all, and without the todo that excuses the gap.
    let probe_at = no_port.find("[[recognize.probes]]").unwrap();
    let version_at = no_port.find("[version]").unwrap();
    let no_probe = format!("{}{}", &no_port[..probe_at], &no_port[version_at..]);
    let no_todo = replaced(
        &no_probe,
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
    k("blind_spot = ", "note = ", "an unknown key");
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
        "[[recognize.probes]]\nkind = \"http\"\nmethod = \"GET\"\npath = \"/\"\nfield = \"x\"\nmatch = '^x$'\n\n[version]",
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
    // A wildcard covers a later image of the same prefix: strfry claims `lnd-*`,
    // lnd's own image becomes `lnd-x`.
    let mut files = entry_files();
    for (stem, from, to) in [
        (
            "strfry",
            "images = [\"ghcr.io/hoytech/strfry\"]",
            "images = [\"docker.io/lightninglabs/lnd-*\"]",
        ),
        (
            "lnd",
            "images = [\"docker.io/lightninglabs/lnd\"]",
            "images = [\"docker.io/lightninglabs/lnd-x\"]",
        ),
    ] {
        let f = files.iter_mut().find(|(s, _)| s == stem).unwrap();
        f.1 = replaced(&f.1, from, to);
    }
    let err = catalog::load_all(&pairs(&files)).unwrap_err().to_string();
    assert!(err.contains("overlap"), "{err}");
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
        assert_eq!(e.id(), stem);
        assert!(!e.display_name().is_empty());
        assert!(!e.osv_packages().is_empty(), "{stem}");
    }
    // Sorted by id.
    let ids: Vec<&str> = cat.entries().map(|e| e.id()).collect();
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
    let ids: Vec<&str> = cat.entries_on_port(9735).iter().map(|e| e.id()).collect();
    assert!(ids.len() >= 2, "{ids:?}");
    assert!(
        ids.contains(&"lnd") && ids.contains(&"core-lightning"),
        "{ids:?}"
    );
    let mut sorted = ids.clone();
    sorted.sort_unstable();
    assert_eq!(ids, sorted);
    // One owner, and none.
    let relay: Vec<&str> = cat.entries_on_port(7777).iter().map(|e| e.id()).collect();
    assert_eq!(relay, ["strfry"]);
    assert!(cat.entries_on_port(1).is_empty());
    assert!(cat.entries_on_port(65535).is_empty());
}

/// The identity probe reply of each network-source entry that matches it.
const IDENTITY_REPLIES: [(&str, &str); 4] = [
    ("bitcoin-core", "/Satoshi:32.1.0/"),
    ("lnd", "SERVER_ACTIVE"),
    ("nutshell", "Nutshell/0.21.0"),
    ("strfry", "git+https://github.com/hoytech/strfry.git"),
];

/// The key of the one endpoint the tests observe.
fn ep() -> EndpointKey {
    EndpointKey::new("host-a.test", 7777)
}

/// The proof of identity for an entry, from its probe reply; panics when it is not `Read`.
fn identified<'e>(e: &'e Entry, reply: &str) -> Identified<'e> {
    match e.identify_endpoint(&ep(), &[u(reply)]) {
        ReplyMatch::Read(i) => i,
        other => panic!("{}: not identified: {other:?}", e.id()),
    }
}

#[test]
fn identity_comes_before_the_version() {
    // Codex catalog r2 HIGH 1: a version is read only from an identified product.
    let cat = catalog::embedded().unwrap();
    let fry = cat.get("strfry").unwrap();
    assert!(matches!(
        fry.identify_endpoint(&ep(), &[u("other-relay")]),
        ReplyMatch::NoMatch
    ));
    let id = identified(fry, "git+https://github.com/hoytech/strfry.git");
    assert_eq!(
        id.read_version(&ep(), &u("1.1.2")),
        VersionMatch::Read("1.1.2")
    );
    assert_eq!(id.entry().id(), "strfry");
    assert_eq!(id.by(), IdentifiedBy::Probes);
    // The wrong number of replies, or none, is missing evidence.
    assert!(matches!(
        fry.identify_endpoint(&ep(), &[]),
        ReplyMatch::Unreadable(Unreadable::MissingEvidence)
    ));
    assert!(matches!(
        fry.identify_endpoint(&ep(), &[u("a"), u("b")]),
        ReplyMatch::Unreadable(Unreadable::MissingEvidence)
    ));

    // Bitcoin Core: the identity probe refuses Knots and anything partial.
    let core = cat.get("bitcoin-core").unwrap();
    let id = identified(core, "/Satoshi:32.1.0/");
    assert_eq!(
        id.read_version(&ep(), &u("/Satoshi:32.1.0/")),
        VersionMatch::Read("32.1")
    );
    for raw in [
        "/Satoshi:28.1.0/Knots:20250305/",
        "x/Satoshi:32.1.0/",
        "/Satoshi:32.1.0/ ",
    ] {
        assert!(
            matches!(
                core.identify_endpoint(&ep(), &[u(raw)]),
                ReplyMatch::NoMatch
            ),
            "{raw}"
        );
    }

    // Evidence kind: the version source says which evidence it can use.
    let lnd = cat.get("lnd").unwrap();
    let by_probe = identified(lnd, "SERVER_ACTIVE");
    assert_eq!(
        by_probe.read_version(&ep(), &u("0.21.6-beta")),
        VersionMatch::Read("0.21.6-beta")
    );
    let by_image = match lnd.identify_image(&u("lightninglabs/lnd:v0.21.6-beta")) {
        ReplyMatch::Read(i) => i,
        other => panic!("{other:?}"),
    };
    assert_eq!(by_image.by(), IdentifiedBy::Image);
    assert_eq!(
        by_image.read_version(
            &EndpointKey::for_image(&u("lightninglabs/lnd:v0.21.6-beta")),
            &u("0.21.6-beta")
        ),
        VersionMatch::Unreadable(Unreadable::MissingEvidence)
    );
    let cln = cat.get("core-lightning").unwrap();
    let cln_image = match cln.identify_image(&u("elementsproject/lightningd:v26.06.9")) {
        ReplyMatch::Read(i) => i,
        other => panic!("{other:?}"),
    };
    assert_eq!(
        cln_image.read_version(
            &EndpointKey::for_image(&u("elementsproject/lightningd:v26.06.9")),
            &u("v26.06.9")
        ),
        VersionMatch::Read("26.06.9")
    );
    assert!(matches!(
        cln.identify_endpoint(&ep(), &[]),
        ReplyMatch::Unreadable(Unreadable::MissingEvidence)
    ));

    // identify_image.
    let tapd = cat.get("tapd").unwrap();
    // An entry with no images cannot be identified by image: cannot tell, not "no".
    assert!(matches!(
        tapd.identify_image(&u("docker.io/lightninglabs/tapd")),
        ReplyMatch::Unreadable(Unreadable::MissingEvidence)
    ));
    assert!(matches!(
        cat.get("alby-hub")
            .unwrap()
            .identify_image(&u("getalby/hub:v1.19.0")),
        ReplyMatch::Unreadable(Unreadable::MissingEvidence)
    ));
    assert!(matches!(
        lnd.identify_image(&u("docker.io/evil/lnd")),
        ReplyMatch::NoMatch
    ));
    assert!(matches!(
        lnd.identify_image(&u("lnd\u{1b}[31m")),
        ReplyMatch::Unreadable(Unreadable::BadToken)
    ));
    assert!(matches!(
        lnd.identify_image(&u(&"a".repeat(MAX_REPLY + 1))),
        ReplyMatch::Unreadable(Unreadable::TooLong)
    ));
    assert!(matches!(
        lnd.identify_image(&u("lnd\u{e9}")),
        ReplyMatch::Unreadable(Unreadable::NonAscii)
    ));
    assert_eq!(
        format!("{by_probe:?}"),
        "Identified { entry: \"lnd\", by: Probes }"
    );

    // The Pattern-level reply cap: 256 bytes are read, 257 are Unreadable (version
    // unknown), never NoMatch, whatever the pattern says.
    let pat = Pattern::new(r"^(?P<version>\d+)$").unwrap();
    assert_eq!(
        pat.version(&u(&"7".repeat(MAX_REPLY + 1))),
        ReplyMatch::Unreadable(Unreadable::TooLong)
    );
    assert_eq!(
        pat.matches(&u(&"7".repeat(MAX_REPLY + 1))),
        ReplyMatch::Unreadable(Unreadable::TooLong)
    );
    assert_eq!(
        pat.matches(&u(&"7".repeat(MAX_REPLY))),
        ReplyMatch::Read(())
    );
    // A matching reply whose token is too long (256 digits) is a bad token, not a no-match.
    assert_eq!(
        pat.version(&u(&"7".repeat(MAX_REPLY))),
        ReplyMatch::Unreadable(Unreadable::BadToken)
    );
    // An alternation cannot match part of a reply (the \A(?:...)\z wrapper).
    let alt = Pattern::new(r"^nomatch|(?P<version>\d+)\.0$").unwrap();
    assert_eq!(alt.version(&u("junk 9.0")), ReplyMatch::NoMatch);
    assert_eq!(alt.version(&u("9.0")), ReplyMatch::Read("9"));
    // Even a pattern that accepts any text gives out only a clean token.
    let any = Pattern::new(r"^(?P<version>.+)$").unwrap();
    assert_eq!(
        any.version(&u("1.2.3-rc.1+build~5")),
        ReplyMatch::Read("1.2.3-rc.1+build~5")
    );
    for bad in [
        "1 2",
        "1\n2",
        "<b>1</b>",
        "1;2",
        "../x",
        "١.٢",
        "é",
        "\u{1b}[31m",
        "--rpc-file",
        "..",
        "-1",
        ".1",
        "+1",
        "~1",
    ] {
        assert!(!any.version(&u(bad)).is_read(), "{bad:?}");
    }
    assert_eq!(
        any.version(&u(&"1".repeat(64))).read().map(str::len),
        Some(64)
    );
    assert_eq!(
        any.version(&u(&"1".repeat(65))),
        ReplyMatch::Unreadable(Unreadable::BadToken)
    );
    // `\d` is ASCII in a catalog pattern: non-ASCII digits are Unreadable.
    let digits = Pattern::new(r"^(?P<version>\d+)$").unwrap();
    assert_eq!(
        digits.matches(&u("١٢٣")),
        ReplyMatch::Unreadable(Unreadable::NonAscii)
    );
}

#[test]
fn an_identified_product_with_an_unreadable_version_is_kept() {
    // Codex catalog r2 HIGH 3: an identified product whose version cannot be read
    // is version unknown with the product kept: the type has no `NoMatch` for a
    // version. (The inventory-level check, product kept and version Unknown,
    // belongs to the scanner PR, which has no code yet.)
    let cat = catalog::embedded().unwrap();
    let lnd = cat.get("lnd").unwrap();
    let id = identified(lnd, "SERVER_ACTIVE");
    for raw in ["", "garbage", "0.21.6"] {
        assert_eq!(
            id.read_version(&ep(), &u(raw)),
            VersionMatch::Unreadable(Unreadable::NotAVersion),
            "{raw:?}"
        );
    }
    assert_eq!(
        id.read_version(&ep(), &u(&"1".repeat(MAX_REPLY + 1))),
        VersionMatch::Unreadable(Unreadable::TooLong)
    );
    assert_eq!(
        id.read_version(&ep(), &u("١.٢.٣-beta")),
        VersionMatch::Unreadable(Unreadable::NonAscii)
    );
    // A release candidate is identified by Bitcoin Core's probe, and its version is unread.
    let core = cat.get("bitcoin-core").unwrap();
    let rc = identified(core, "/Satoshi:0.21.0rc1/");
    assert_eq!(
        rc.read_version(&ep(), &u("/Satoshi:0.21.0rc1/")),
        VersionMatch::Unreadable(Unreadable::NotAVersion)
    );
    // Every network-source entry: an identified read of a 257-byte reply is TooLong.
    let mut seen = Vec::new();
    for e in cat.entries() {
        if !matches!(
            e.version_call().source(),
            catalog::Source::Rpc
                | catalog::Source::Grpc
                | catalog::Source::Http
                | catalog::Source::Nip11
        ) {
            continue;
        }
        let (_, reply) = IDENTITY_REPLIES
            .iter()
            .find(|(i, _)| *i == e.id())
            .unwrap_or_else(|| panic!("{}: add its identity reply to IDENTITY_REPLIES", e.id()));
        let id = identified(e, reply);
        let long = format!("{}{}", "1".repeat(MAX_REPLY), ".0.0");
        assert_eq!(
            id.read_version(&ep(), &u(&long)),
            VersionMatch::Unreadable(Unreadable::TooLong),
            "{}",
            e.id()
        );
        seen.push(e.id());
    }
    assert_eq!(seen.len(), IDENTITY_REPLIES.len(), "{seen:?}");
}

#[test]
fn a_network_source_needs_an_identity_probe() {
    // Codex catalog r2 HIGH 1: no identity check on the endpoint, no network source.
    let lnd = text_of("lnd");
    let block = "[[recognize.probes]]\nkind = \"grpc\"\nmethod = \"lnrpc.State/GetState\"\nport = 10009\nfield = \"state\"\nmatch = '^(?:NON_EXISTING|LOCKED|UNLOCKED|RPC_ACTIVE|SERVER_ACTIVE|WAITING_TO_START)$'\n\n";
    refused(
        "lnd",
        &replaced(&lnd, block, ""),
        "a network source needs a recognize.probes item",
    );
    // A probe on another port is not the identity of this endpoint.
    let nutshell = text_of("nutshell");
    let moved = replaced(
        &nutshell,
        "[[recognize.probes]]\nkind = \"http\"",
        "[[recognize.ports]]\nport = 9999\nproto = \"tcp\"\nwhat = \"other\"\nexposure = \"lan\"\n\n[[recognize.probes]]\nkind = \"http\"",
    );
    let moved = replaced(
        &moved,
        "path = \"/v1/info\"\nport = 3338\nfield",
        "path = \"/v1/info\"\nport = 9999\nfield",
    );
    refused(
        "nutshell",
        &moved,
        "a network source needs a recognize.probes item",
    );
}

#[test]
fn version_call_exposes_what_the_scanner_needs() {
    let cat = catalog::embedded().unwrap();
    let lnd = cat.get("lnd").unwrap();
    let v = lnd.version_call();
    assert_eq!(v.source(), catalog::Source::Grpc);
    assert_eq!(v.endpoint_port(), Some(10009));
    assert_eq!(v.call().field(), "version");
    assert_eq!(
        v.call().call().map(catalog::Call::kind),
        Some(&catalog::CallKind::Grpc {
            method: "verrpc.Versioner/GetVersion".into()
        })
    );
    assert_eq!(v.tls().unwrap().server_name, "localhost");
    assert_eq!(lnd.scheme(), catalog::Scheme::SemverBeta);
    assert_eq!(lnd.display_name(), "LND");
    let fry = cat.get("strfry").unwrap().version_call();
    assert_eq!(
        fry.call().call().map(catalog::Call::kind),
        Some(&catalog::CallKind::Http {
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
name = "Synthetic {id}"
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
    assert_eq!(
        catalog::CATALOG_MAX_PRODUCTS_PER_PORT,
        gd_core::MAX_CANDIDATES
    );
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
    build(gd_core::MAX_CANDIDATES).unwrap();
    let err = build(gd_core::MAX_CANDIDATES + 1).unwrap_err();
    assert!(
        err.to_string().contains("CATALOG_MAX_PRODUCTS_PER_PORT"),
        "{err}"
    );
}

/// A reply, as the scanner would hold it: outside text.
fn u(s: &str) -> Untrusted<String> {
    Untrusted::new(s.to_string())
}

#[test]
fn hardening_cases_are_refused() {
    let core = text_of("bitcoin-core");
    let fry = text_of("strfry");
    let lnd = text_of("lnd");
    let site = "website = \"https://bitcoincore.org/\"";
    let feed = "release_feed = \"https://github.com/bitcoin/bitcoin/releases.atom\"";
    let c = |from: &str, to: &str, want: &str| {
        refused("bitcoin-core", &replaced(&core, from, to), want);
    };

    // URLs: a trailing dot or empty label, and any % encoding.
    for bad in [
        "https://bitcoincore.org./",
        "https://bitcoincore.org../",
        "https://bitcoin..core.org/",
        "https://.bitcoincore.org/",
    ] {
        c(site, &format!("website = \"{bad}\""), "empty label");
    }
    c(
        "repo = \"https://github.com/bitcoin/bitcoin\"",
        "repo = \"https://github.com./bitcoin/bitcoin\"",
        "empty label",
    );
    c(
        feed,
        "release_feed = \"https://github.com/bitcoin/bitcoin/%2e%2e/other/releases.atom\"",
        "% encoding",
    );
    c(
        feed,
        "release_feed = \"https://github.com/bitcoin/bitcoin/releases%2eatom\"",
        "% encoding",
    );
    c(
        site,
        "website = \"https://bitcoincore.org/%2e%2e/\"",
        "% encoding",
    );
    c(
        "source = \"fixtures/lab-recorded/manifest.toml\"",
        "source = \"https://github.com/bitcoin/bitcoin/%2e%2e/x\"",
        "% encoding",
    );

    // Wildcard images need a whole registry/namespace/repo prefix.
    let images = "images = [\"docker.io/bitcoin/bitcoin\"]";
    for bad in [
        "docker.io/*",
        "docker.io/bitcoin/*",
        "docker.io/library*",
        "docker.io/bitcoin*",
        "*",
        "ghcr.io/*",
    ] {
        c(images, &format!("images = [\"{bad}\"]"), "image");
    }
    // A wildcard in the middle of a repo name is refused too (round 2: only after a
    // whole repo name and one of `-`, `_`, `.`).
    c(
        images,
        "images = [\"docker.io/bitcoin/bit*\"]",
        "image wildcard",
    );

    // A (port, proto) twice in one entry; the same port on another protocol is fine.
    let ports = "[[recognize.ports]]\nport = 7777\nproto = \"PROTO\"\nwhat = \"again\"\nexposure = \"lan\"\n\n[version]\n";
    refused(
        "strfry",
        &replaced(&fry, "[version]\n", &ports.replace("PROTO", "tcp")),
        "twice",
    );
    validate(
        "strfry",
        &replaced(&fry, "[version]\n", &ports.replace("PROTO", "udp")),
    )
    .unwrap();

    // Depth: deeply nested TOML is refused, not walked.
    let deep = format!("a = {}1{}\n", "[".repeat(40), "]".repeat(40));
    let err = catalog::scan_secret_shapes(&deep).unwrap_err().to_string();
    assert!(err.contains("deeper"), "{err}");
    assert!(catalog::scan_secret_shapes("a = [[[1]]]\n").is_ok());

    // platform_map.note is one plain line like every other note.
    let map = |note: &str| {
        format!(
            "[[platform_map]]\nplatform = \"umbrelos\"\napp_id = \"lnd\"\nversion_rule = \"same\"\nnote = \"{note}\"\n\n[review]\n"
        )
    };
    refused(
        "lnd",
        &replaced(&lnd, "[review]\n", &map("a\\nb")),
        "platform_map.note",
    );
    refused(
        "lnd",
        &replaced(&lnd, "[review]\n", &map("a\\u001bb")),
        "platform_map.note",
    );
    validate("lnd", &replaced(&lnd, "[review]\n", &map("a plain note"))).unwrap();

    // No fallback to the web's root certificates.
    refused(
        "lnd",
        &replaced(
            &lnd,
            "cert_source = \"node-tls-cert\"",
            "cert_source = \"system-roots\"",
        ),
        "cert_source must be one of",
    );
}

// ---------- round 2: no echo, sweep, wildcards, hosts, advisories, display text ----------

/// The loader's error for an entry text, as the whole message a user would see.
fn load_error(stem: &str, text: &str) -> String {
    catalog::load(stem, text).unwrap_err().to_string()
}

#[test]
fn errors_name_the_field_and_never_echo_values() {
    let lnd = text_of("lnd");
    let feed = "release_feed = \"https://github.com/lightningnetwork/lnd/releases.atom\"";
    // A URL with user info: refused, and neither the user nor the token is in the message.
    let e = load_error(
        "lnd",
        &replaced(
            &lnd,
            feed,
            "release_feed = \"https://alice:t0kenvalue\u{40}github.com/lightningnetwork/lnd/releases.atom\"",
        ),
    );
    assert!(!e.contains("t0kenvalue") && !e.contains("alice"), "{e}");
    assert!(e.contains("upstream.release_feed"), "{e}");
    // An example's raw text holding an xprv-shaped value: caught by the scan first,
    // naming only the field path.
    let xprv = format!("xprv{}", "Abcdefghjkmnpqrstuvwx");
    let e = load_error(
        "lnd",
        &replaced(&lnd, "raw = \"0.21.6-beta\"", &format!("raw = \"{xprv}\"")),
    );
    assert!(!e.contains(&xprv) && !e.contains("Abcdefghjkm"), "{e}");
    assert!(e.contains("version.examples[0].raw"), "{e}");
    // A raw that is not secret-shaped but does not read: no raw text either.
    let e = load_error(
        "lnd",
        &replaced(&lnd, "raw = \"0.21.6-beta\"", "raw = \"zq-9.9.9-beta\""),
    );
    assert!(!e.contains("zq-9.9.9"), "{e}");
    assert!(e.contains("version.examples[0].raw"), "{e}");
    // A bad pattern: its text is not in the message.
    let e = load_error(
        "lnd",
        &replaced(
            &lnd,
            "regex = '^(?P<version>\\d+\\.\\d+\\.\\d+-beta(?:\\.rc\\d+)?)$'",
            "regex = '(?P<version>toppatterntext)'",
        ),
    );
    assert!(!e.contains("toppatterntext"), "{e}");
    // Invalid TOML around a secret: toml's own message would quote the text.
    let e = load_error("lnd", &format!("name = \"{xprv}\" oops\n"));
    assert!(!e.contains(&xprv), "{e}");
    let e = catalog::scan_secret_shapes(&format!("name = \"{xprv}\" oops\n"))
        .unwrap_err()
        .to_string();
    assert!(!e.contains(&xprv), "{e}");
    // A quoted key cannot imitate the fingerprint path to borrow its 40-hex exemption.
    let fp = "0123456789abcdef0123456789abcdef01234567";
    let sneaky = format!("[signing]\n\"keys[0].fingerprint\" = \"{fp}\"\n");
    assert!(catalog::scan_secret_shapes(&sneaky).is_err());
    // The same value in a real fingerprint is fine.
    let real =
        format!("[[signing.keys]]\nwho = \"x\"\nfingerprint = \"{fp}\"\nchecked = 2026-11-17\n");
    assert!(catalog::scan_secret_shapes(&real).is_ok());
}

#[test]
fn plain_version_sweep_refuses_wide_regexes() {
    let tapd = text_of("tapd");
    let rx = "regex = '^(?P<version>0\\.\\d+\\.\\d+)$'";
    let ex = "raw = \"0.5.1\"\nversion = \"0.5.1\"";
    let with = |regex: &str, raw: &str| {
        let t = replaced(&tapd, rx, &format!("regex = '{regex}'"));
        replaced(&t, ex, &format!("raw = \"{raw}\"\nversion = \"{raw}\""))
    };
    // Minor 2 is left out and the minor class skips it: the old sweep missed this.
    refused(
        "tapd",
        &with("^(?P<version>\\d+\\.[013-9]\\.\\d+)$", "0.5.1"),
        "more than one major",
    );
    // Two-part, three-part and four-part plain forms.
    refused(
        "tapd",
        &with("^(?P<version>\\d+\\.\\d+)$", "0.5"),
        "more than one major",
    );
    refused(
        "tapd",
        &with("^(?P<version>\\d+\\.\\d+\\.\\d+\\.\\d+)$", "192.0.2.1"),
        "more than one major",
    );
    refused(
        "tapd",
        &with("^(?P<version>[1-9]\\d*\\.\\d+\\.\\d+)$", "5.1.1"),
        "more than one major",
    );
    // Codex catalog r2 HIGH 5: a wide regex that reads a first major the sweep once
    // missed, a major in the sample range, a one-major regex that is not pinned as
    // written, and a regex whose parts hide a second major.
    refused(
        "tapd",
        &with("^(?P<version>(?:0|41|42)\\.\\d+\\.\\d+)$", "0.5.1"),
        "more than one major",
    );
    refused(
        "tapd",
        &with("^(?P<version>(?:0|777)\\.\\d+\\.\\d+)$", "0.5.1"),
        "more than one major",
    );
    refused(
        "tapd",
        &with("^(?P<version>(?:0)\\.\\d+\\.\\d+)$", "0.5.1"),
        "must pin that major",
    );
    refused(
        "tapd",
        &with("^(?P<version>0\\.\\d+\\.\\d+)?(?:5\\.\\d+)?$", "0.5.1"),
        "major",
    );
    // Opus r3 LOW 1: minors and patches past 12 are sampled too.
    refused(
        "tapd",
        &with("^(?P<version>\\d+\\.[1-9]\\d\\.\\d+)$", "0.18.3"),
        "more than one major",
    );
    refused(
        "tapd",
        &with("^(?P<version>\\d+\\.\\d\\.[1-9]\\d\\d)$", "0.1.123"),
        "more than one major",
    );
    // Codex r3 MED 3: an optional separator or an alternation in the pinned part does
    // not get past the structural check, and the sweep and the match-time major check
    // agree on `1.12.7` (see also the unit test in the loader for `112.7`).
    refused(
        "tapd",
        &with("^(?P<version>0\\.?12\\.7)$", "0.12.7"),
        "must pin that major",
    );
    refused(
        "alby-hub",
        &replaced(
            &text_of("alby-hub"),
            "regex = '^(?P<version>1\\.\\d+\\.\\d+)$'",
            "regex = '^(?P<version>(?:1|2)\\.19\\.0)$'",
        ),
        "must pin that major",
    );
    // A regex pinned to one major still loads (the shipped 0.x and 2.x entries).
    validate("tapd", &tapd).unwrap();
}

#[test]
fn wildcard_images_follow_a_whole_repo_name() {
    let lnd = text_of("lnd");
    let images = "images = [\"docker.io/lightninglabs/lnd\"]";
    for ok in [
        "docker.io/lightninglabs/lnd-*",
        "docker.io/lightninglabs/lnd_*",
        "docker.io/lightninglabs/lnd.*",
    ] {
        validate(
            "lnd",
            &replaced(&lnd, images, &format!("images = [\"{ok}\"]")),
        )
        .unwrap();
    }
    for bad in [
        "docker.io/library/a*",
        "docker.io/library/nginx-*",
        "docker.io/lightninglabs/l*",
        "docker.io/lightninglabs/lnd*",
        "docker.io/lightninglabs/-*",
        "docker.io/light*/lnd-*",
        "docker.io/lightning-*/lnd",
        "docker.io/bitcoin/bit*",
    ] {
        refused(
            "lnd",
            &replaced(&lnd, images, &format!("images = [\"{bad}\"]")),
            "image",
        );
    }
}

#[test]
fn website_never_vouches_for_keys_or_feeds_and_shared_hosts_are_refused() {
    let core = text_of("bitcoin-core");
    let site = "website = \"https://bitcoincore.org/\"";
    for bad in [
        "https://github.com/bitcoin/bitcoin",
        "https://www.github.com/",
        "https://gist.github.com/x",
        "https://raw.githubusercontent.com/",
        "https://objects.githubusercontent.com/",
        "https://gitlab.com/bitcoin/bitcoin",
        "https://foo.gitlab.com/",
        "https://bitbucket.org/bitcoin/bitcoin",
        "https://bitcoin.readthedocs.io/",
    ] {
        refused(
            "bitcoin-core",
            &replaced(&core, site, &format!("website = \"{bad}\"")),
            "shared code host",
        );
    }
    // The website does not vouch for keys_url or an advisory feed.
    let keys = "keys_url = \"https://github.com/bitcoin-core/guix.sigs/tree/main/builder-keys\"";
    refused(
        "bitcoin-core",
        &replaced(&core, keys, "keys_url = \"https://bitcoincore.org/keys\""),
        "website does not vouch",
    );
    let feeds = "feeds = [{ kind = \"markdown-repo\", url = \"https://github.com/bitcoin-core/bitcoincore.org\" }]";
    refused(
        "bitcoin-core",
        &replaced(
            &core,
            feeds,
            "feeds = [{ kind = \"atom\", url = \"https://bitcoincore.org/feed.xml\" }]",
        ),
        "website does not vouch",
    );
    // A related repo of the same owner still can.
    validate(
        "bitcoin-core",
        &replaced(
            &core,
            keys,
            "keys_url = \"https://github.com/bitcoin-core/bitcoincore.org/tree/main/keys\"",
        ),
    )
    .unwrap();
    // A github.io website is allowed as a website only: it vouches for nothing.
    let pages = replaced(&core, site, "website = \"https://bitcoin.github.io/\"");
    validate("bitcoin-core", &pages).unwrap();
    refused(
        "bitcoin-core",
        &replaced(
            &pages,
            "release_feed = \"https://github.com/bitcoin/bitcoin/releases.atom\"",
            "release_feed = \"https://bitcoin.github.io/releases.atom\"",
        ),
        "not under upstream",
    );
}

#[test]
fn related_repos_share_the_owner_and_odd_hosts_are_refused() {
    let core = text_of("bitcoin-core");
    refused(
        "bitcoin-core",
        &replaced(
            &core,
            "https://github.com/bitcoin-core/guix.sigs\",\n",
            "https://github.com/other/guix.sigs\",\n",
        ),
        "same code host and owner",
    );
    let site = "website = \"https://bitcoincore.org/\"";
    for bad in [
        "https://0x7f.example.com/",
        "https://example.0x7f/",
        "https://example.123abc/",
        "https://xn--bcher-kva.example.com/",
        "https://example.xn--p1ai/",
    ] {
        refused(
            "bitcoin-core",
            &replaced(&core, site, &format!("website = \"{bad}\"")),
            "URL host must not use",
        );
    }
}

#[test]
fn advisories_need_a_package_and_a_known_ecosystem() {
    let lnd = text_of("lnd");
    let core = text_of("bitcoin-core");
    let pkg = "osv_packages = [\"Go github.com/lightningnetwork/lnd\"]";
    // No package and no blind_spot: nothing can match, and nothing says so.
    refused(
        "lnd",
        &replaced(&lnd, pkg, "osv_packages = []"),
        "blind_spot",
    );
    // With a blind_spot, an empty list is an honest statement.
    let with_spot = replaced(
        &lnd,
        pkg,
        "osv_packages = []\nblind_spot = \"No OSV package.\"",
    );
    validate("lnd", &with_spot).unwrap();
    // Ecosystem names are OSV's, exactly.
    for bad in ["go", "Gp", "Cargo", "PYPI", "Docker"] {
        refused(
            "lnd",
            &replaced(
                &lnd,
                pkg,
                &format!("osv_packages = [\"{bad} github.com/lightningnetwork/lnd\"]"),
            ),
            "ecosystem must be one of",
        );
    }
    for ok in [
        "Go",
        "PyPI",
        "npm",
        "crates.io",
        "Maven",
        "NuGet",
        "RubyGems",
        "Packagist",
        "Hex",
        "Pub",
        "SwiftURL",
        "Debian",
        "Alpine",
        "Ubuntu",
    ] {
        validate(
            "lnd",
            &replaced(
                &lnd,
                pkg,
                &format!("osv_packages = [\"{ok} some-package\"]"),
            ),
        )
        .unwrap();
    }
    // GIT: the name is the repo or a related repo.
    let git = "osv_packages = [\"GIT https://github.com/bitcoin/bitcoin\"]";
    refused(
        "bitcoin-core",
        &replaced(
            &core,
            git,
            "osv_packages = [\"GIT https://github.com/bitcoin/other\"]",
        ),
        "GIT package must be",
    );
    validate(
        "bitcoin-core",
        &replaced(
            &core,
            git,
            "osv_packages = [\"GIT https://github.com/bitcoin-core/guix.sigs\"]",
        ),
    )
    .unwrap();
}

#[test]
fn display_text_has_no_hidden_characters_and_names_are_unique() {
    let lnd = text_of("lnd");
    for bad in [
        "\u{200b}", "\u{200f}", "\u{202a}", "\u{202e}", "\u{2066}", "\u{2069}", "\u{feff}",
        "\u{00ad}",
    ] {
        refused(
            "lnd",
            &replaced(
                &lnd,
                "summary = \"Lightning Labs' Lightning Network node.\"",
                &format!("summary = \"Lightning Labs'{bad} node.\""),
            ),
            "format or bidi",
        );
    }
    refused(
        "lnd",
        &replaced(&lnd, "name = \"LND\"", "name = \"L\u{200b}ND\""),
        "entry.name",
    );
    // A name must be ASCII, so no look-alike letters.
    refused(
        "lnd",
        &replaced(&lnd, "name = \"LND\"", "name = \"L\u{039d}D\""),
        "ASCII",
    );
    // Opus catalog r2 LOW: no leading, trailing or doubled space, so two names
    // that look the same can never both exist.
    for bad in ["LND ", " LND", "L  ND"] {
        refused(
            "lnd",
            &replaced(&lnd, "name = \"LND\"", &format!("name = \"{bad}\"")),
            "entry.name must not start or end",
        );
    }
    let a = synthetic("one-svc");
    let b = replaced(
        &synthetic("two-svc"),
        "name = \"Synthetic two-svc\"",
        "name = \"Synthetic one-svc \"",
    );
    let err = catalog::load_all(&[("one-svc", &a), ("two-svc", &b)]).unwrap_err();
    assert!(
        err.to_string().contains("entry.name must not start or end"),
        "{err}"
    );
    // Names are unique across the catalog, ignoring case.
    let a = synthetic("one-svc");
    let b = replaced(
        &synthetic("two-svc"),
        "name = \"Synthetic two-svc\"",
        "name = \"SYNTHETIC ONE-SVC\"",
    );
    let err = catalog::load_all(&[("one-svc", &a), ("two-svc", &b)]).unwrap_err();
    assert!(err.to_string().contains("display name"), "{err}");
}

#[test]
fn example_raw_is_untrusted_and_probes_need_a_pattern() {
    let cat = catalog::embedded().unwrap();
    let lnd = cat.get("lnd").unwrap();
    let ex = &lnd.version_call().examples()[0];
    // Debug never shows the reply, and the text comes out only through an escaping call.
    assert_eq!(format!("{:?}", ex.raw), "Untrusted(<hidden>)");
    assert_eq!(ex.raw.escape_for_terminal(), "0.21.6-beta");
    // A probe with no pattern is refused at load.
    let text = text_of("lnd");
    refused(
        "lnd",
        &replaced(
            &text,
            "field = \"state\"\nmatch = '^(?:NON_EXISTING|LOCKED|UNLOCKED|RPC_ACTIVE|SERVER_ACTIVE|WAITING_TO_START)$'\n",
            "",
        ),
        "a probe needs both field and match",
    );
    // The probe's pattern three-way result.
    let probe = &lnd.recognize().probes[0];
    assert_eq!(probe.field(), "state");
    assert_eq!(probe.matches(&u("SERVER_ACTIVE")), ReplyMatch::Read(()));
    assert_eq!(probe.matches(&u("nope")), ReplyMatch::NoMatch);
    assert_eq!(
        probe.matches(&u(&"A".repeat(MAX_REPLY + 1))),
        ReplyMatch::Unreadable(Unreadable::TooLong)
    );
}

#[test]
fn link_checks_survive_a_long_chain_and_still_find_cycles() {
    // A chain of 300 entries, each bundling the next: no recursion, no overflow.
    let n = 300;
    let texts: Vec<(String, String)> = (0..n)
        .map(|i| {
            let id = format!("c-{i}");
            let mut t = synthetic(&id);
            // Distinct ports per entry would be needed only past the cap; use no ports.
            t = t.replace(
                "[[recognize.ports]]\nport = 9735\nproto = \"tcp\"\nwhat = \"peer\"\nexposure = \"lan\"\n\n",
                "",
            );
            t = t.replace("endpoint_port = 9735\n", "");
            if i + 1 < n {
                t = t.replacen("aliases = []", &format!("aliases = []\nbundles = [\"c-{}\"]", i + 1), 1);
            }
            (id, t)
        })
        .collect();
    catalog::load_all(&pairs(&texts)).unwrap();
    // A cycle is still found.
    let a = replaced(
        &synthetic("aa"),
        "aliases = []",
        "aliases = []\nbundles = [\"bb\"]",
    );
    let b = replaced(
        &synthetic("bb"),
        "aliases = []",
        "aliases = []\nbundles = [\"aa\"]",
    );
    let a = replaced(&a, "name = \"Synthetic aa\"", "name = \"Synthetic aa\"");
    let err = catalog::load_all(&[("aa", &a), ("bb", &b)]).unwrap_err();
    assert!(err.to_string().contains("cycle"), "{err}");
}

// ---------- round 3: trust roots, work budget, no quoting, recorded replies ----------

#[test]
fn trust_roots_are_on_a_reviewed_forge_in_a_fixed_shape() {
    // Codex catalog r2 HIGH 4: a repo on an unreviewed host, and a trust root that
    // is a page anyone can write, are refused.
    let lnd = text_of("lnd");
    let moved = lnd.replace(
        "https://github.com/lightningnetwork/lnd",
        "https://example.org/team/lnd",
    );
    refused("lnd", &moved, "reviewed code host");
    let keys = "keys_url = \"https://github.com/lightningnetwork/lnd/tree/master/scripts/keys\"";
    for bad in [
        "issues/1234",
        "pull/1/files",
        "discussions/5",
        "wiki/Keys",
        "tree/refs/pull/1/head",
        "",
    ] {
        let url = if bad.is_empty() {
            "https://github.com/lightningnetwork/lnd".to_string()
        } else {
            format!("https://github.com/lightningnetwork/lnd/{bad}")
        };
        let text = replaced(&lnd, keys, &format!("keys_url = \"{url}\""));
        refused("lnd", &text, "signing.keys_url must be a release feed");
        let e = load_error("lnd", &text);
        // The URL's own path is never quoted back.
        for part in ["issues", "pull/1", "wiki/Keys", "discussions/5"] {
            assert!(!e.contains(part), "{e}");
        }
    }
    let feed = "release_feed = \"https://github.com/lightningnetwork/lnd/releases.atom\"";
    refused(
        "lnd",
        &replaced(
            &lnd,
            feed,
            "release_feed = \"https://github.com/lightningnetwork/lnd/issues.atom\"",
        ),
        "upstream.release_feed must be a release feed",
    );
    validate("lnd", &lnd).unwrap();

    // Opus r3 MED 2: a ref anyone can write (an abbreviated commit reachable from a
    // fork, a pull-request ref, HEAD in any case) is not a trust root.
    for bad in [
        "tree/1a2b3c4d5e6f/scripts/keys",
        "tree/1A2B/scripts/keys",
        "tree/pull/1/head/keys",
        "tree/Pull/1/head/keys",
        "blob/HEAD/SECURITY.md",
        "blob/head/SECURITY.md",
        "tree/refs/pull/1/head",
    ] {
        let url = format!("https://github.com/lightningnetwork/lnd/{bad}");
        let text = replaced(&lnd, keys, &format!("keys_url = \"{url}\""));
        refused("lnd", &text, "signing.keys_url must be a release feed");
        let policy = replaced(&lnd, feed, &format!("{feed}\nsecurity_policy = \"{url}\""));
        refused(
            "lnd",
            &policy,
            "upstream.security_policy must be a release feed",
        );
    }
    // Branch and tag shaped names still load.
    for ok in ["master", "v0.21.6-beta", "release-0.20", "abc"] {
        let url = format!("https://github.com/lightningnetwork/lnd/tree/{ok}/scripts/keys");
        validate(
            "lnd",
            &replaced(&lnd, keys, &format!("keys_url = \"{url}\"")),
        )
        .unwrap();
    }

    // Opus r3 MED 1 and Codex r3 MED 4: on a code host the website is the repo, so it
    // never rescues a URL that fails the repo's path shape.
    let base = synthetic("cb-svc").replace("github.com", "codeberg.org");
    let repo = "repo = \"https://codeberg.org/o/cb-svc\"";
    let with = |extra: &str| {
        replaced(
            &base,
            repo,
            &format!("{repo}\nwebsite = \"https://codeberg.org/o/cb-svc\"\n{extra}"),
        )
    };
    validate(
        "cb-svc",
        &with("release_feed = \"https://codeberg.org/o/cb-svc/releases.atom\""),
    )
    .unwrap();
    for bad in ["/issues/1", "/wiki/Home", "/pulls/3"] {
        refused(
            "cb-svc",
            &with(&format!(
                "release_feed = \"https://codeberg.org/o/cb-svc{bad}\""
            )),
            "upstream.release_feed must be a release feed",
        );
        refused(
            "cb-svc",
            &with(&format!(
                "security_policy = \"https://codeberg.org/o/cb-svc{bad}\""
            )),
            "upstream.security_policy must be a release feed",
        );
    }
}

#[test]
fn catalog_work_is_bounded() {
    // Codex catalog r2 MED 1: an entry, a list, the images and the catalog are capped.
    let lnd = text_of("lnd");
    let pad = 32_769 - lnd.len() - 3;
    let big = format!("{lnd}# {}\n", "x".repeat(pad));
    assert_eq!(big.len(), 32_769);
    refused("lnd", &big, "larger than 32768 bytes");
    let e = catalog::scan_secret_shapes(&big).unwrap_err().to_string();
    assert!(e.contains("larger than 32768 bytes"), "{e}");

    let images = "images = [\"docker.io/lightninglabs/lnd\"]";
    let list = |n: usize| {
        let items: Vec<String> = (0..n).map(|i| format!("\"docker.io/o/i{i}\"")).collect();
        format!("images = [{}]", items.join(", "))
    };
    refused(
        "lnd",
        &replaced(&lnd, images, &list(65)),
        "has more than 64 items",
    );
    refused(
        "lnd",
        &replaced(&lnd, images, &list(17)),
        "recognize.images has more than 16 items",
    );
    refused(
        "lnd",
        &replaced(
            &lnd,
            images,
            "images = [\"docker.io/lightninglabs/lnd\", \"docker.io/lightninglabs/lnd\"]",
        ),
        "recognize.images[1] repeats recognize.images[0]",
    );
    // The count check runs before any entry is parsed (the texts are empty).
    let many: Vec<(String, &str)> = (0..1025).map(|i| (format!("x{i}"), "")).collect();
    let files: Vec<(&str, &str)> = many.iter().map(|(n, t)| (n.as_str(), *t)).collect();
    let e = catalog::load_all(&files).unwrap_err().to_string();
    assert!(e.contains("more than 1024 entries"), "{e}");
}

#[test]
fn errors_never_quote_untrusted_values() {
    // Codex catalog r2 MED 2 and Opus r2 LOW 2: an error names a field and an
    // index, never a value from the entry (or the caller's name for it).
    let check = |err: catalog::CatalogError, label: &str| {
        let shown = err.to_string();
        let debug = format!("{err:?}");
        for text in [&shown, &debug] {
            assert!(!text.to_lowercase().contains("qzxmark"), "{text}");
            assert!(!text.contains('\u{1b}'), "{text:?}");
            assert!(text.contains(label), "{text} (wanted `{label}`)");
        }
    };
    let lnd = text_of("lnd");
    let cln = text_of("core-lightning");
    let nutshell = text_of("nutshell");
    check(catalog::load("QZXMARK\u{1b}", &lnd).unwrap_err(), "<entry>");
    let load = |stem: &str, text: &str| catalog::load(stem, text).unwrap_err();
    check(
        load(
            "lnd",
            &replaced(&lnd, "id = \"lnd\"", "id = \"QZXMARK\\u001b[31m\""),
        ),
        "entry.id",
    );
    check(
        load(
            "lnd",
            &replaced(
                &lnd,
                "aliases = []",
                "aliases = []\nbundles = [\"QZXMARK\\u001b\"]",
            ),
        ),
        "entry.bundles[0]",
    );
    let argv = "argv = [\"lightning-cli\", \"getinfo\"]";
    for (to, label) in [
        ("[\"QZXMARK/x\", \"getinfo\"]", "version.call.argv[0]"),
        ("[\"lightning-cli\", \"QZXMARK;x\"]", "version.call.argv[1]"),
        ("[\"lightning-cli\", \"qzxmark\"]", "READ_ONLY_CALLS"),
    ] {
        check(
            load(
                "core-lightning",
                &replaced(&cln, argv, &format!("argv = {to}")),
            ),
            label,
        );
    }
    check(
        load(
            "nutshell",
            &replaced(
                &nutshell,
                "path = \"/v1/info\"",
                "path = \"/QZXMARK\\u001b\"",
            ),
        ),
        "recognize.probes.path",
    );
    check(
        load(
            "lnd",
            &replaced(
                &lnd,
                "method = \"lnrpc.State/GetState\"",
                "method = \"QZXMARK;x\"",
            ),
        ),
        "recognize.probes.method",
    );
    check(
        load(
            "lnd",
            &replaced(&lnd, "field = \"state\"", "field = \"QZXMARK\\u001b\""),
        ),
        "recognize.probes.field",
    );
    let one = replaced(
        &synthetic("one-svc"),
        "images = [\"docker.io/o/one-svc\"]",
        "images = [\"docker.io/o/qzxmark\"]",
    );
    let two = replaced(
        &synthetic("two-svc"),
        "images = [\"docker.io/o/two-svc\"]",
        "images = [\"docker.io/o/qzxmark\"]",
    );
    check(
        catalog::load_all(&[("one-svc", &one), ("two-svc", &two)]).unwrap_err(),
        "recognize.images",
    );
    // Codex r3 MED 5: an unknown key is shown as a fixed placeholder, in the loader's
    // own message and in the paths the secret scan builds.
    check(
        load(
            "lnd",
            &replaced(&lnd, "format = 1\n", "format = 1\nQZXMARK = true\n"),
        ),
        "an unknown key",
    );
    check(
        load(
            "lnd",
            &replaced(&lnd, "[review]\n", "[review]\nQZXMARK = true\n"),
        ),
        "an unknown key in review",
    );
    let token = format!("ghp_{}", "a1B2".repeat(10));
    check(
        load(
            "lnd",
            &replaced(
                &lnd,
                "format = 1\n",
                &format!("format = 1\nQZXMARK = \"{token}\"\n"),
            ),
        ),
        "<key> has a secret shape",
    );
    let e = load(
        "lnd",
        &replaced(&lnd, "releases.atom\"", "releases\u{202e}.atom\""),
    );
    check(e.clone(), "upstream.release_feed");
    assert!(e.to_string().contains("URL must be ASCII"), "{e}");
}

/// A field of a recorded JSON reply, as outside text. `path` is dotted.
fn recorded_field(file: &str, path: &str) -> Untrusted<String> {
    let mut v: serde_json::Value =
        serde_json::from_str(&read(&format!("fixtures/lab-recorded/replies/{file}"))).unwrap();
    for part in path.split('.') {
        v = v[part].take();
    }
    u(v.as_str()
        .unwrap_or_else(|| panic!("{file} {path} is not a string")))
}

#[test]
fn probes_read_the_recorded_replies() {
    // Opus catalog r2 LOW 3: each entry's identity probe and version regex read the
    // lab's own recorded replies. The lnd file is the REST `GET /v1/state` reply; its
    // `state` is the same as gRPC `GetState`'s, which the probe calls today (K1 moves
    // the probe to REST).
    let cat = catalog::embedded().unwrap();
    let rec = recordings(&read("fixtures/lab-recorded/manifest.toml"));
    let cases = [
        (
            "lnd",
            recorded_field("lnd/state.json", "state"),
            recorded_field("lnd/versioner-version.json", "version"),
            "0.21.6-beta",
        ),
        (
            "strfry",
            recorded_field("strfry/nip11.json", "software"),
            recorded_field("strfry/nip11.json", "version"),
            "1.1.2-148-g4cd3cf6",
        ),
        (
            "nutshell",
            recorded_field("nutshell/info.json", "version"),
            recorded_field("nutshell/info.json", "version"),
            "0.21.0",
        ),
        (
            "bitcoin-core",
            recorded_field("bitcoind/getnetworkinfo.json", "result.subversion"),
            recorded_field("bitcoind/getnetworkinfo.json", "result.subversion"),
            "32.1",
        ),
    ];
    for (id, probe_reply, version_reply, expected) in &cases {
        let e = cat.get(id).unwrap();
        let proof = match e.identify_endpoint(&ep(), std::slice::from_ref(probe_reply)) {
            ReplyMatch::Read(i) => i,
            other => panic!("{id}: {other:?}"),
        };
        assert_eq!(
            proof.read_version(&ep(), version_reply),
            VersionMatch::Read(expected),
            "{id}"
        );
        let manifest = rec.iter().find(|r| r.id == *id).unwrap();
        assert_eq!(manifest.version, *expected, "{id}");
    }
    // Cross-check: lnd's probe does not read strfry's recorded reply.
    let lnd = cat.get("lnd").unwrap();
    let fry_software = recorded_field("strfry/nip11.json", "software");
    assert!(matches!(
        lnd.identify_endpoint(&ep(), &[fry_software]),
        ReplyMatch::NoMatch
    ));
}

#[test]
fn reviewed_url_exceptions_are_each_needed() {
    // Opus catalog r2 LOW 4: every reviewed exception is used, and adding one means
    // editing this test.
    assert_eq!(OTHER_URLS.len(), 1);
    assert_eq!(RELATED_OTHER_OWNER.len(), 1);
    let cat = catalog::embedded().unwrap();
    let owner_of = |url: &str| -> String {
        url.strip_prefix("https://")
            .and_then(|r| r.split('/').nth(1))
            .unwrap_or("")
            .to_ascii_lowercase()
    };
    let under = |url: &str, base: &str| {
        let base = base.trim_end_matches('/');
        url == base || url.strip_prefix(base).is_some_and(|r| r.starts_with('/'))
    };
    for (id, field, prefix) in OTHER_URLS {
        let e = cat
            .get(id)
            .unwrap_or_else(|| panic!("{id} is not an entry"));
        let urls: Vec<&str> = match field {
            "upstream.release_feed" => e
                .upstream()
                .release_feed
                .iter()
                .map(String::as_str)
                .collect(),
            "upstream.security_policy" => e
                .upstream()
                .security_policy
                .iter()
                .map(String::as_str)
                .collect(),
            "signing.keys_url" => e.signing().keys_url.iter().map(String::as_str).collect(),
            "advisories.feeds.url" => e
                .advisories()
                .feeds
                .iter()
                .map(|f| f.url.as_str())
                .collect(),
            other => panic!("{id}: {other} is not a field an exception can name"),
        };
        let mut own: Vec<&str> = vec![&e.upstream().repo];
        own.extend(e.upstream().related_repos.iter().map(String::as_str));
        own.extend(e.upstream().website.as_deref());
        assert!(
            urls.iter()
                .any(|u| under(u, prefix) && !own.iter().any(|b| under(u, b))),
            "{id}: no {field} needs the exception for {prefix}"
        );
    }
    for (id, owner, _) in RELATED_OTHER_OWNER {
        let e = cat
            .get(id)
            .unwrap_or_else(|| panic!("{id} is not an entry"));
        assert!(
            e.upstream()
                .related_repos
                .iter()
                .any(|r| owner_of(r) == *owner),
            "{id}: no related repo is owned by {owner}"
        );
        assert_ne!(owner_of(&e.upstream().repo), *owner, "{id}");
    }
}

#[test]
fn identity_matches_the_product_marker_only() {
    // Opus r3 MED 3 and Codex r3 MED 1: a probe recognises the product by its own
    // marker, never by the version form, so an odd version is "version unknown"
    // with the product kept, not "not this product".
    let cat = catalog::embedded().unwrap();
    let core = cat.get("bitcoin-core").unwrap();
    let id = identified(core, "/Satoshi:28.1.0(mynode)/");
    assert_eq!(
        id.read_version(&ep(), &u("/Satoshi:28.1.0(mynode)/")),
        VersionMatch::Unreadable(Unreadable::NotAVersion)
    );
    for ok in ["/Satoshi:32.1.0/", "/Satoshi:28.0.0rc1/", "/Satoshi:30.2/"] {
        assert!(identified(core, ok).entry().id() == "bitcoin-core", "{ok}");
    }
    for raw in [
        "/Knots:20250305/",
        "/Satoshi:28.1.0/Knots:20250305/",
        "/Other:28.1.0/",
        "/Satoshi:/",
        "/Satoshi:x28/",
    ] {
        assert!(
            matches!(
                core.identify_endpoint(&ep(), &[u(raw)]),
                ReplyMatch::NoMatch
            ),
            "{raw}"
        );
    }
    let nut = cat.get("nutshell").unwrap();
    let id = identified(nut, "Nutshell/0.21.0-rc1");
    assert_eq!(
        id.read_version(&ep(), &u("Nutshell/0.21.0-rc1")),
        VersionMatch::Unreadable(Unreadable::NotAVersion)
    );
    assert_eq!(
        identified(nut, "Nutshell/0.21.0").read_version(&ep(), &u("Nutshell/0.21.0")),
        VersionMatch::Read("0.21.0")
    );
    for raw in [
        "Other/0.21.0",
        "nutshell/0.21.0",
        "Nutshell/",
        "Nutshell/0.21.0 ",
    ] {
        assert!(
            matches!(nut.identify_endpoint(&ep(), &[u(raw)]), ReplyMatch::NoMatch),
            "{raw}"
        );
    }
}

#[test]
fn identity_is_bound_to_one_observation() {
    // Opus r3 LOW 3 and Codex r3 MED 2: proof from one endpoint is not used for another's reply.
    let cat = catalog::embedded().unwrap();
    let fry = cat.get("strfry").unwrap();
    let a = EndpointKey::new("relay-a.test", 7777);
    let b = EndpointKey::new("relay-b.test", 7777);
    assert!(a == EndpointKey::new("RELAY-A.test", 7777));
    assert!(a != b);
    assert!(a != EndpointKey::new("relay-a.test", 7778));
    let proof = match fry.identify_endpoint(&a, &[u("git+https://github.com/hoytech/strfry.git")]) {
        ReplyMatch::Read(i) => i,
        other => panic!("{other:?}"),
    };
    // B reports other software; A's proof with B's key (and B's reply) is not a read.
    assert!(matches!(
        fry.identify_endpoint(&b, &[u("other-relay")]),
        ReplyMatch::NoMatch
    ));
    assert_eq!(
        proof.read_version(&b, &u("1.1.2")),
        VersionMatch::Unreadable(Unreadable::MissingEvidence)
    );
    assert_eq!(
        proof.read_version(&a, &u("1.1.2")),
        VersionMatch::Read("1.1.2")
    );
    // The key shows nothing of its contents.
    assert_eq!(format!("{a:?}"), "EndpointKey(..)");
    // An image proof is bound to the image (tag and digest do not matter).
    let cli = cat.get("core-lightning").unwrap();
    let img = u("elementsproject/lightningd:v26.06.9");
    let by_image = match cli.identify_image(&img) {
        ReplyMatch::Read(i) => i,
        other => panic!("{other:?}"),
    };
    let same = EndpointKey::for_image(&u("docker.io/elementsproject/lightningd:v26.06.8"));
    assert_eq!(
        by_image.read_version(&same, &u("v26.06.9")),
        VersionMatch::Read("26.06.9")
    );
    assert_eq!(
        by_image.read_version(
            &EndpointKey::for_image(&u("lightninglabs/lnd")),
            &u("v26.06.9")
        ),
        VersionMatch::Unreadable(Unreadable::MissingEvidence)
    );
    assert_eq!(
        by_image.read_version(&a, &u("v26.06.9")),
        VersionMatch::Unreadable(Unreadable::MissingEvidence)
    );
}

#[test]
fn image_references_are_checked_before_they_are_normalised() {
    // Codex r3 MED 7 and Opus r3 NIT: a reference with a missing tag or digest, `..` or an
    // odd path is not well formed, so it never identifies anything.
    let cat = catalog::embedded().unwrap();
    let cln = cat.get("core-lightning").unwrap();
    for bad in [
        "elementsproject/lightningd@",
        "elementsproject/lightningd:",
        "elementsproject/lightningd@sha256:abc@def",
        "elementsproject//lightningd",
        "/elementsproject/lightningd",
        "elementsproject/lightningd/",
        "elementsproject/../lightningd",
        "elementsproject/./lightningd",
        "docker.io/elementsproject/lightningd:a:b",
        ":v1",
    ] {
        assert!(
            matches!(
                cln.identify_image(&u(bad)),
                ReplyMatch::Unreadable(Unreadable::BadToken)
            ),
            "{bad}"
        );
    }
    for ok in [
        "elementsproject/lightningd",
        "elementsproject/lightningd:v26.06.9",
        "elementsproject/lightningd@sha256:0123abcd",
        "docker.io/elementsproject/lightningd:v26.06.9@sha256:0123abcd",
    ] {
        assert!(cln.identify_image(&u(ok)).is_read(), "{ok}");
    }
    // A wildcard covers one more repo name, never a deeper path or `..`.
    let wild = catalog::load(
        "one-svc",
        &replaced(
            &synthetic("one-svc"),
            "images = [\"docker.io/o/one-svc\"]",
            "images = [\"docker.io/o/one-svc-*\"]",
        ),
    )
    .unwrap();
    assert!(wild.identify_image(&u("o/one-svc-x:1")).is_read());
    for deeper in ["o/one-svc-x/y", "docker.io/o/one-svc-x/y/z"] {
        assert!(
            matches!(wild.identify_image(&u(deeper)), ReplyMatch::NoMatch),
            "{deeper}"
        );
    }
    assert!(matches!(
        wild.identify_image(&u("o/one-svc-x/../y")),
        ReplyMatch::Unreadable(Unreadable::BadToken)
    ));
    // A registry port is fine.
    assert!(matches!(
        cln.identify_image(&u("localhost:5000/elementsproject/lightningd:v1")),
        ReplyMatch::NoMatch
    ));
}

#[test]
fn a_secret_in_a_comment_is_refused() {
    // Codex r3 HIGH: comments are never parsed, but the file is embedded as written, so
    // the credential-shape scan runs over the raw text, every line.
    let lnd = text_of("lnd");
    let token = format!("ghp_{}", "a1B2".repeat(10));
    let lines = lnd.lines().count();
    let in_comment = format!("{lnd}# note: {token}\n");
    let e = load_error("lnd", &in_comment);
    assert!(
        e.contains(&format!("line {} has a secret shape", lines + 1)),
        "{e}"
    );
    assert!(!e.contains(&token[..8]), "{e}");
    // A trailing comment on a value line, and a comment above the first line.
    refused(
        "lnd",
        &replaced(&lnd, "money = true", &format!("money = true # {token}")),
        "has a secret shape",
    );
    refused(
        "lnd",
        &format!("# {token}\n{lnd}"),
        "line 1 has a secret shape",
    );
    let e = catalog::scan_secret_shapes(&in_comment)
        .unwrap_err()
        .to_string();
    assert!(e.contains("has a secret shape"), "{e}");
    assert!(!format!("{e:?}").contains(&token), "{e}");
    // The same for a 40-hex string in a comment (a fingerprint is only allowed as a value).
    refused(
        "lnd",
        &format!("{lnd}# {}\n", &"0123456789abcdef".repeat(3)[..40]),
        "has a secret shape",
    );
    // A catalog of files refuses it too, naming the file's slug.
    let err = catalog::load_all(&[("lnd", &in_comment)])
        .unwrap_err()
        .to_string();
    assert!(err.contains("lnd") && err.contains("secret shape"), "{err}");
    // Plain comments are fine.
    validate(
        "lnd",
        &format!("{lnd}# a plain note, version 2.4.1 at 12:30\n"),
    )
    .unwrap();
}

#[test]
fn embedded_files_pass_the_raw_secret_scan() {
    // The text compiled into the binary is the raw file, comments included.
    for (id, text) in catalog::embedded_files() {
        catalog::scan_secret_shapes(text).unwrap_or_else(|e| panic!("{id}: {e}"));
    }
}

#[test]
fn citations_resolve_only_against_the_trusted_inventory() {
    // Codex r3 MED 6: an example or port `source` is looked up in the inventory of
    // repo files (found without following symlinks); it is never joined to a path
    // or shown in a failure.
    let inv = inventory();
    assert!(inv.contains("lab/compose.yml"));
    assert!(inv.contains("fixtures/lab-recorded/manifest.toml"));
    source_exists(&inv, "version.examples.source", 0, "lab/compose.yml").unwrap();
    source_exists(&inv, "version.examples.source", 0, "https://github.com/o/p").unwrap();
    for bad in [
        "fixtures/QZXMARK",
        "../etc/passwd",
        "/etc/passwd",
        "fixtures/../Cargo.toml",
        "Cargo.toml",
        "fixtures",
    ] {
        let e = source_exists(&inv, "version.examples.source", 3, bad).unwrap_err();
        assert!(e.starts_with("version.examples.source (item 3)"), "{e}");
        assert!(
            !e.to_lowercase().contains("qzxmark") && !e.contains("passwd"),
            "{e}"
        );
    }
    // A symlink is not in the inventory, whatever it points at.
    #[cfg(unix)]
    {
        let dir = std::env::temp_dir().join(format!("gd-inventory-{}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("sub")).unwrap();
        fs::write(dir.join("real.txt"), "x").unwrap();
        std::os::unix::fs::symlink(root().join("Cargo.toml"), dir.join("sub/link.txt")).unwrap();
        std::os::unix::fs::symlink(dir.join("sub"), dir.join("linkdir")).unwrap();
        let mut found = BTreeSet::new();
        walk_files(&dir, "x", &mut found);
        fs::remove_dir_all(&dir).unwrap();
        assert_eq!(found, BTreeSet::from(["x/real.txt".to_string()]));
    }
}
