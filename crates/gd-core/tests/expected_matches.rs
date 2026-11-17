//! Judge B, steps 3 and 5: the expected advisory matches in
//! `fixtures/expected-matches.toml`, written by hand before any matcher
//! exists, and the judge that scores a matcher against them.
//!
//! Deterministic: no network, no Docker, no clock. Advisory ids, packages,
//! platform scopes and condition services come from `advisories/corpus/*.json`;
//! the lab's service versions come from the pinned image labels in
//! `lab/compose.yml` (the labels `lab/up.sh` checks the running services
//! against). Everything is kept in sorted maps and sets.
//!
//! Platform scoping: an affected[] entry with `database_specific.platform`
//! applies only to setups on that platform (`PLATFORM_SCOPES`). An entry that
//! doesn't apply is ignored by the version call, the same rule the file's
//! header states.

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

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::path::{Path, PathBuf};

use toml::{Table, Value};
use yaml_rust2::YamlLoader;

const FILE: &str = "fixtures/expected-matches.toml";
/// The setups judged today, in file order. A new setup is added here and in the file.
const SETUPS: [&str; 2] = ["lab-old-synthetic", "lab-regtest"];
const RESULTS: [&str; 3] = ["affected", "not-affected", "possibly-affected"];
const VERSION_STATES: [&str; 4] = ["in-range", "out-of-range", "unknown", "not-applicable"];
const CONDITION_STATES: [&str; 3] = ["met", "not-met", "unknown"];
const ARCHES: [&str; 2] = ["32-bit", "64-bit"];
/// The closed chain names: the same five as the fact model's `Chain` enum.
const CHAINS: [&str; 5] = ["main", "testnet3", "testnet4", "signet", "regtest"];
const TOP_KEYS: [&str; 4] = ["expect", "format", "product", "setup"];
const PRODUCT_KEYS: [&str; 3] = ["aliases", "id", "packages"];
const SETUP_KEYS: [&str; 13] = [
    "arch",
    "block_storage",
    "chain",
    "description",
    "exposure",
    "fact",
    "id",
    "package",
    "packages_from",
    "platform",
    "service",
    "source",
    "versions_from",
];
const SERVICE_KEYS: [&str; 2] = ["id", "version"];
const FACT_KEYS: [&str; 5] = ["evidence", "name", "service", "subject", "value"];
const FACT_VALUES: [&str; 3] = ["true", "false", "unknown"];
/// Condition names that take an argument; a fact for one carries it as `subject`.
const ARGUMENT_FACTS: [&str; 5] = [
    "backend_in_use",
    "feature_enabled",
    "option_disabled",
    "option_enabled",
    "package_installed",
];
const PACKAGE_KEYS: [&str; 4] = ["evidence", "in", "product", "version"];
const EXPECT_KEYS: [&str; 8] = [
    "advisory",
    "condition",
    "question",
    "reason",
    "result",
    "review",
    "setup",
    "version",
];

fn on_64_bit(arch: &str, _storage: &str) -> bool {
    arch == "64-bit"
}
fn on_32_bit_or_fat32(arch: &str, storage: &str) -> bool {
    arch == "32-bit" || storage == "fat32"
}

/// Does a scoped entry apply to a setup with this arch and block storage?
type ScopeRule = fn(&str, &str) -> bool;

/// Every per-entry `database_specific.platform` text in the corpus, and
/// whether that entry applies to a setup with this arch and block storage.
/// A new platform text in the corpus fails `every_platform_scope_is_understood`.
const PLATFORM_SCOPES: [(&str, ScopeRule); 2] = [
    ("64-bit systems, including Windows", on_64_bit),
    (
        "32-bit systems, or blocks stored on a FAT32 file system",
        on_32_bit_or_fat32,
    ),
];

/// One expectation. Private to the judge: a matcher never sees it.
#[derive(Debug, Clone)]
struct Expect {
    setup: String,
    advisory: String,
    result: String,
}

/// All a matcher is given: which setup, which advisory. Never the answer.
#[derive(Debug, Clone, Copy)]
struct MatchInput<'a> {
    setup: &'a str,
    advisory: &'a str,
}

/// One affected[] entry: its package (`<ecosystem> <name>`) and platform scope.
struct Entry {
    package: String,
    platform: Option<String>,
}

/// One required condition of an advisory: its fact name and its argument, if any.
struct Required {
    name: String,
    subject: Option<String>,
    service: Option<String>,
    /// For `chain`-like conditions: the values that make the condition true.
    any_of: Option<Vec<String>>,
}

struct Corpus {
    entries: BTreeMap<String, Vec<Entry>>,
    condition_services: BTreeSet<String>,
    /// Every condition fact name any advisory uses.
    condition_names: BTreeSet<String>,
    /// Each advisory's required conditions (those without `required = false`).
    required: BTreeMap<String, Vec<Required>>,
    /// Every condition of every advisory, required or not.
    conditions: Vec<Required>,
}

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(rel: &str) -> String {
    let path = root().join(rel);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()))
}

fn corpus() -> Corpus {
    let dir = root().join("advisories/corpus");
    let mut paths: Vec<PathBuf> = fs::read_dir(&dir)
        .unwrap()
        .map(|e| e.unwrap().path())
        .filter(|p| p.extension().and_then(|e| e.to_str()) == Some("json"))
        .collect();
    paths.sort();
    let mut c = Corpus {
        entries: BTreeMap::new(),
        condition_services: BTreeSet::new(),
        condition_names: BTreeSet::new(),
        required: BTreeMap::new(),
        conditions: Vec::new(),
    };
    for path in paths {
        let v: serde_json::Value = serde_json::from_str(&fs::read_to_string(&path).unwrap())
            .unwrap_or_else(|e| panic!("{} is not JSON: {e}", path.display()));
        let entries = v["affected"]
            .as_array()
            .unwrap()
            .iter()
            .map(|a| Entry {
                package: format!(
                    "{} {}",
                    a["package"]["ecosystem"].as_str().unwrap(),
                    a["package"]["name"].as_str().unwrap()
                ),
                platform: a["database_specific"]["platform"]
                    .as_str()
                    .map(str::to_owned),
            })
            .collect();
        let id = v["id"].as_str().unwrap().to_owned();
        let mut required = Vec::new();
        for cond in v["database_specific"]["guard_dog"]["conditions"]
            .as_array()
            .unwrap()
        {
            if let Some(s) = cond["service"].as_str() {
                c.condition_services.insert(s.to_owned());
            }
            let name = cond["fact"].as_str().unwrap().to_owned();
            c.condition_names.insert(name.clone());
            // The argument: option, backend (`value`), feature or package.
            let subject = ["option", "value", "feature", "package"]
                .iter()
                .find_map(|k| cond[*k].as_str())
                .map(str::to_owned);
            let any_of = cond["any_of"].as_array().map(|a| {
                a.iter()
                    .filter_map(|v| v.as_str().map(str::to_owned))
                    .collect()
            });
            let make = || Required {
                name: name.clone(),
                subject: subject.clone(),
                service: cond["service"].as_str().map(str::to_owned),
                any_of: any_of.clone(),
            };
            c.conditions.push(make());
            if cond["required"].as_bool() != Some(false) {
                required.push(make());
            }
        }
        c.required.insert(id.clone(), required);
        c.entries.insert(id, entries);
    }
    assert!(!c.entries.is_empty(), "no advisories in {}", dir.display());
    c
}

/// The lab's services as `lab/up.sh` pins them: the id label to the
/// expected-version label of each service in `lab/compose.yml`.
fn lab_versions() -> BTreeMap<String, String> {
    let up = read("lab/up.sh");
    for needle in ["org.guard-dog.lab.", "expected-version"] {
        assert!(
            up.contains(needle),
            "lab/up.sh no longer reads the `{needle}` labels; this test's source of truth has moved"
        );
    }
    let docs = YamlLoader::load_from_str(&read("lab/compose.yml")).unwrap();
    let mut out = BTreeMap::new();
    for svc in docs[0]["services"].as_hash().unwrap().values() {
        let labels = &svc["labels"];
        let id = labels["org.guard-dog.lab.id"].as_str().unwrap();
        let version = labels["org.guard-dog.lab.expected-version"]
            .as_str()
            .unwrap();
        assert!(
            out.insert(id.to_owned(), version.to_owned()).is_none(),
            "duplicate lab id {id}"
        );
    }
    out
}

fn is_slug(s: &str) -> bool {
    !s.is_empty()
        && s.split('-').all(|part| {
            !part.is_empty()
                && part
                    .chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        })
}

/// Printable ASCII on one line, no surrounding spaces: what every text field must be.
fn is_clean_line(s: &str) -> bool {
    !s.is_empty() && s.trim() == s && s.chars().all(|c| (' '..='~').contains(&c))
}

fn unknown_keys(table: &Table, allowed: &[&str], what: &str, errors: &mut Vec<String>) {
    for key in table.keys() {
        if !allowed.contains(&key.as_str()) {
            errors.push(format!("{what}: unknown key `{key}`"));
        }
    }
}

fn text<'a>(table: &'a Table, key: &str, what: &str, errors: &mut Vec<String>) -> &'a str {
    match table.get(key) {
        Some(Value::String(s)) if is_clean_line(s) => s,
        Some(_) => {
            errors.push(format!(
                "{what}: `{key}` must be one line of printable ASCII text"
            ));
            ""
        }
        None => {
            errors.push(format!("{what}: `{key}` is missing"));
            ""
        }
    }
}

fn texts(table: &Table, key: &str, what: &str, errors: &mut Vec<String>) -> Vec<String> {
    match table.get(key).and_then(Value::as_array) {
        Some(items) => items
            .iter()
            .filter_map(|i| match i.as_str() {
                Some(s) if is_clean_line(s) => Some(s.to_owned()),
                _ => {
                    errors.push(format!("{what}: `{key}` items must be one-line text"));
                    None
                }
            })
            .collect(),
        None => {
            errors.push(format!("{what}: `{key}` must be an array"));
            Vec::new()
        }
    }
}

fn tables<'a>(v: Option<&'a Value>, what: &str, errors: &mut Vec<String>) -> Vec<&'a Table> {
    match v {
        Some(Value::Array(items)) => items
            .iter()
            .filter_map(|i| {
                let t = i.as_table();
                if t.is_none() {
                    errors.push(format!("{what}: every item must be a table"));
                }
                t
            })
            .collect(),
        _ => {
            errors.push(format!("{what}: must be an array of tables"));
            Vec::new()
        }
    }
}

/// The result the version and condition calls imply (see the file's header).
fn implied(version: &str, condition: &str) -> &'static str {
    if version == "out-of-range" || condition == "not-met" {
        "not-affected"
    } else if version == "in-range" && condition == "met" {
        "affected"
    } else {
        "possibly-affected"
    }
}

fn scope_applies(platform: &str, arch: &str, storage: &str) -> Option<bool> {
    PLATFORM_SCOPES
        .iter()
        .find(|(name, _)| *name == platform)
        .map(|(_, applies)| applies(arch, storage))
}

/// What a setup is, as far as matching goes.
struct Setup {
    arch: String,
    storage: String,
    /// The OSV packages of every product present in the setup.
    packages: BTreeSet<String>,
    /// The setup's top-level `chain`.
    chain: String,
    /// Each `[[setup.fact]]`: its name and its subject.
    facts: Vec<(String, Option<String>)>,
    /// Does the setup record package versions (`[[setup.package]]`)?
    has_packages: bool,
    /// Ids of the services the setup runs.
    services: BTreeSet<String>,
    /// Products with a recorded package version other than "none".
    package_products: BTreeSet<String>,
    /// Each fact row.
    fact_rows: Vec<FactRow>,
}

struct FactRow {
    name: String,
    subject: Option<String>,
    service: Option<String>,
    value: String,
}

/// Every pair marked `review = "max"`, exactly. Adding or removing a review
/// mark means editing this list too.
const REVIEW_PAIRS: [(&str, &str); 4] = [
    ("lab-old-synthetic", "CVE-2025-46598"),
    ("lab-old-synthetic", "CVE-2026-117349"),
    (
        "lab-old-synthetic",
        "x_cln-2026-v26.06.8-unspecified-vulnerabilities",
    ),
    ("lab-regtest", "CVE-2026-117346"),
];

/// Advisories whose conditions the vendor withheld: in range, their pair is
/// possibly-affected with condition `unknown`; out of range the condition may
/// be met or unknown, never not-met. They are left out of the facts rule.
const UNDISCLOSED_CONDITIONS: [&str; 1] = ["x_cln-2026-v26.06.8-unspecified-vulnerabilities"];

/// What the setup says about one required condition: `Some(true)`,
/// `Some(false)`, or `None` (unknown: no row, or a row saying "unknown").
/// A fact row answers a condition only for the same service: the service
/// itself when the setup runs it, no service when it does not.
fn condition_value(
    req: &Required,
    s: &Setup,
    alias_to_id: &BTreeMap<String, String>,
) -> Option<bool> {
    match req.name.as_str() {
        "chain" => return req.any_of.as_ref().map(|any| any.contains(&s.chain)),
        "service_running" => {
            let id = alias_to_id.get(req.service.as_deref()?)?;
            return Some(s.services.contains(id));
        }
        _ => {}
    }
    let want: Option<Option<String>> = req
        .service
        .as_ref()
        .and_then(|c| alias_to_id.get(c))
        .map(|id| s.services.contains(id).then(|| id.clone()));
    let row = s.fact_rows.iter().find(|r| {
        r.name == req.name
            && (req.subject.is_none() || r.subject == req.subject)
            && want.as_ref().is_none_or(|w| r.service == *w)
    });
    if let Some(r) = row {
        return match r.value.as_str() {
            "true" => Some(true),
            "false" => Some(false),
            _ => None,
        };
    }
    if req.name == "package_installed" && s.has_packages {
        let subject = req.subject.as_deref()?;
        return Some(s.package_products.iter().any(|p| {
            alias_to_id
                .iter()
                .any(|(alias, id)| id == p && subject.split(' ').any(|w| w == alias))
        }));
    }
    None
}

/// A local path in text: evidence must not leak where someone's files live.
/// Any word that is an absolute path, a home path, a drive path or an
/// environment-variable path.
fn has_local_path(s: &str) -> bool {
    s.contains("$HOME")
        || s.contains("%USERPROFILE%")
        || s.split_whitespace().any(|w| {
            let w = w.trim_start_matches(['(', '"', '\'', '`', '=']);
            let b = w.as_bytes();
            w.starts_with('/')
                || w.starts_with("~/")
                || w == "~"
                || w.starts_with('$')
                || (b.len() >= 3
                    && b[0].is_ascii_alphabetic()
                    && b[1] == b':'
                    && matches!(b[2], b'\\' | b'/'))
        })
}

/// Check the whole file. Returns the expectations, or every problem found.
fn check(
    text_in: &str,
    corpus: &Corpus,
    lab: &BTreeMap<String, String>,
) -> Result<Vec<Expect>, Vec<String>> {
    let mut errors = Vec::new();
    let doc: Table = match text_in.parse() {
        Ok(t) => t,
        Err(e) => return Err(vec![format!("not TOML: {e}")]),
    };
    unknown_keys(&doc, &TOP_KEYS, "top level", &mut errors);
    if doc.get("format").and_then(Value::as_integer) != Some(1) {
        errors.push("top level: `format` must be 1".to_owned());
    }

    // Products: catalog id to OSV packages; every name (id or alias) unique.
    let mut products: BTreeMap<String, Vec<String>> = BTreeMap::new();
    let mut names = BTreeSet::new();
    let mut alias_to_id: BTreeMap<String, String> = BTreeMap::new();
    for p in tables(doc.get("product"), "product", &mut errors) {
        unknown_keys(p, &PRODUCT_KEYS, "product", &mut errors);
        let id = text(p, "id", "product", &mut errors).to_owned();
        let what = format!("product {id}");
        if !is_slug(&id) {
            errors.push(format!("{what}: id is not a lower-case slug"));
        }
        for name in std::iter::once(id.clone()).chain(texts(p, "aliases", &what, &mut errors)) {
            alias_to_id.insert(name.clone(), id.clone());
            if !names.insert(name.clone()) {
                errors.push(format!("{what}: name `{name}` is used twice"));
            }
        }
        let packages = texts(p, "packages", &what, &mut errors);
        for pkg in &packages {
            if pkg.split(' ').filter(|s| !s.is_empty()).count() != 2 {
                errors.push(format!(
                    "{what}: package `{pkg}` is not `<ecosystem> <name>`"
                ));
            }
        }
        if products.insert(id.clone(), packages).is_some() {
            errors.push(format!("{what}: listed twice"));
        }
    }
    for cond in corpus.conditions.iter().filter(|c| c.name == "chain") {
        match &cond.any_of {
            Some(any) if !any.is_empty() => {
                for v in any.iter().filter(|v| !CHAINS.contains(&v.as_str())) {
                    errors.push(format!(
                        "a chain condition in the corpus has `{v}`, not one of {CHAINS:?}"
                    ));
                }
            }
            _ => errors.push("a chain condition in the corpus needs a non-empty any_of".to_owned()),
        }
    }
    for service in &corpus.condition_services {
        if !names.contains(service) {
            errors.push(format!(
                "condition service `{service}` in the corpus is not a known product id or alias"
            ));
        }
    }

    // Setups.
    let mut setups: BTreeMap<String, Setup> = BTreeMap::new();
    let mut order = Vec::new();
    for (i, s) in tables(doc.get("setup"), "setup", &mut errors)
        .into_iter()
        .enumerate()
    {
        unknown_keys(s, &SETUP_KEYS, &format!("setup {i}"), &mut errors);
        let id = text(s, "id", &format!("setup {i}"), &mut errors).to_owned();
        let what = format!("setup {id}");
        if !is_slug(&id) {
            errors.push(format!("{what}: id is not a lower-case slug"));
        }
        for key in ["platform", "exposure"] {
            text(s, key, &what, &mut errors);
        }
        let chain = text(s, "chain", &what, &mut errors).to_owned();
        if !CHAINS.contains(&chain.as_str()) {
            errors.push(format!("{what}: chain `{chain}` is not one of {CHAINS:?}"));
        }
        let storage = text(s, "block_storage", &what, &mut errors).to_owned();
        let arch = text(s, "arch", &what, &mut errors).to_owned();
        if !ARCHES.contains(&arch.as_str()) {
            errors.push(format!("{what}: arch `{arch}` is not one of {ARCHES:?}"));
        }
        let mut present = BTreeSet::new();
        let mut services = BTreeMap::new();
        for svc in tables(s.get("service"), &format!("{what} service"), &mut errors) {
            unknown_keys(svc, &SERVICE_KEYS, &format!("{what} service"), &mut errors);
            let sid = text(svc, "id", &what, &mut errors).to_owned();
            let version = text(svc, "version", &what, &mut errors).to_owned();
            if !products.contains_key(&sid) {
                errors.push(format!("{what}: service `{sid}` is not a product id"));
            }
            present.insert(sid.clone());
            if services.insert(sid.clone(), version).is_some() {
                errors.push(format!("{what}: service `{sid}` listed twice"));
            }
        }
        if s.contains_key("package") {
            if !s.contains_key("packages_from") {
                errors.push(format!(
                    "{what}: package versions need `packages_from`, how they were read"
                ));
            }
            for pkg in tables(s.get("package"), &format!("{what} package"), &mut errors) {
                unknown_keys(pkg, &PACKAGE_KEYS, &format!("{what} package"), &mut errors);
                let inside = text(pkg, "in", &what, &mut errors);
                let product = text(pkg, "product", &what, &mut errors);
                let version = text(pkg, "version", &what, &mut errors);
                text(pkg, "evidence", &what, &mut errors);
                if !services.contains_key(inside) {
                    errors.push(format!(
                        "{what}: package is in `{inside}`, not a service here"
                    ));
                }
                if !products.contains_key(product) {
                    errors.push(format!("{what}: package product `{product}` is unknown"));
                }
                if version != "none" {
                    present.insert(product.to_owned());
                }
            }
        }
        if s.contains_key("packages_from") {
            text(s, "packages_from", &what, &mut errors);
        }
        let description = text(s, "description", &what, &mut errors);
        let source = text(s, "source", &what, &mut errors);
        let versions_from = text(s, "versions_from", &what, &mut errors);
        match (source, versions_from) {
            ("lab", "lab/compose.yml") => {
                if &services != lab {
                    errors.push(format!(
                        "{what}: services and versions {services:?} differ from the \
                         lab's pinned images {lab:?}"
                    ));
                }
            }
            ("synthetic", "synthetic") => {
                if !description.starts_with("SYNTHETIC") {
                    errors.push(format!(
                        "{what}: a synthetic setup's description must start with SYNTHETIC"
                    ));
                }
            }
            (src, from) => errors.push(format!(
                "{what}: source `{src}` with versions_from `{from}` is not a known source of truth"
            )),
        }
        // Setup facts: the closed table the matcher reads instead of prose.
        let mut facts: Vec<(String, Option<String>)> = Vec::new();
        let mut fact_rows: Vec<FactRow> = Vec::new();
        let mut by_key: BTreeMap<(String, Option<String>), (Option<String>, String)> =
            BTreeMap::new();
        if let Some(v) = s.get("fact") {
            let fwhat = format!("{what} fact");
            for f in tables(Some(v), &fwhat, &mut errors) {
                unknown_keys(f, &FACT_KEYS, &fwhat, &mut errors);
                let name = text(f, "name", &fwhat, &mut errors).to_owned();
                if !corpus.condition_names.contains(&name) {
                    errors.push(format!(
                        "{fwhat}: name `{name}` is not a condition name used in advisories/corpus"
                    ));
                }
                let service = f
                    .get("service")
                    .map(|_| text(f, "service", &fwhat, &mut errors).to_owned());
                let service = service.as_deref();
                if let Some(sv) = service
                    && !services.contains_key(sv)
                {
                    errors.push(format!(
                        "{fwhat} {name}: service `{sv}` is not a service in this setup"
                    ));
                }
                let subject = f
                    .get("subject")
                    .map(|_| text(f, "subject", &fwhat, &mut errors).to_owned());
                match (ARGUMENT_FACTS.contains(&name.as_str()), &subject) {
                    (true, None) => errors.push(format!(
                        "{fwhat} {name}: a fact with an argument needs a `subject`"
                    )),
                    (false, Some(_)) => errors.push(format!(
                        "{fwhat} {name}: only a fact with an argument has a `subject`"
                    )),
                    _ => {}
                }
                let value = text(f, "value", &fwhat, &mut errors);
                if !FACT_VALUES.contains(&value) {
                    errors.push(format!(
                        "{fwhat} {name}: value `{value}` is not one of {FACT_VALUES:?}"
                    ));
                }
                let evidence = text(f, "evidence", &fwhat, &mut errors);
                if has_local_path(evidence) {
                    errors.push(format!("{fwhat} {name}: evidence names a local path"));
                }
                if name == "service_running" || name == "chain" {
                    errors.push(format!(
                        "{fwhat} {name}: the setup's services and chain already carry this; no row"
                    ));
                }
                // A row answers only the service its condition names: that
                // service when the setup runs it; when it doesn't, no service
                // and the value false (the service is absent, so its option
                // can't be on).
                let named: Vec<String> = corpus
                    .conditions
                    .iter()
                    .filter(|c| c.name == name && c.subject == subject)
                    .filter_map(|c| c.service.as_ref().and_then(|x| alias_to_id.get(x)))
                    .cloned()
                    .collect();
                if !named.is_empty() {
                    match service {
                        Some(sv) if !named.iter().any(|n| n == sv) => errors.push(format!(
                            "{fwhat} {name}: service `{sv}` is not a service any advisory condition names for this fact ({named:?})"
                        )),
                        Some(_) => {}
                        None => {
                            if named.iter().any(|n| services.contains_key(n)) {
                                errors.push(format!(
                                    "{fwhat} {name}: the setup runs the service this fact is about, so the row needs its `service`"
                                ));
                            } else if value != "false" {
                                errors.push(format!(
                                    "{fwhat} {name}: the setup doesn't run the service, so with no `service` the value must be false"
                                ));
                            }
                        }
                    }
                }
                let key = (name.clone(), subject.clone());
                let row = (service.map(str::to_owned), value.to_owned());
                match by_key.get(&key) {
                    Some(prev) if *prev == row => {
                        errors.push(format!("{fwhat} {name}: listed twice"));
                    }
                    Some(_) => errors.push(format!(
                        "{fwhat} {name}: two rows for the same fact with conflicting service or value"
                    )),
                    None => {
                        by_key.insert(key, row);
                    }
                }
                fact_rows.push(FactRow {
                    name: name.clone(),
                    subject: subject.clone(),
                    service: service.map(str::to_owned),
                    value: value.to_owned(),
                });
                facts.push((name, subject));
            }
        }
        let has_packages = s.contains_key("package");
        let package_products: BTreeSet<String> = tables(s.get("package"), "", &mut Vec::new())
            .into_iter()
            .filter(|p| p.get("version").and_then(Value::as_str) != Some("none"))
            .filter_map(|p| p.get("product").and_then(Value::as_str).map(str::to_owned))
            .collect();
        let packages = present
            .iter()
            .filter_map(|p| products.get(p))
            .flatten()
            .cloned()
            .collect();
        order.push(id.clone());
        setups.insert(
            id,
            Setup {
                arch,
                storage,
                packages,
                chain,
                facts,
                has_packages,
                services: services.keys().cloned().collect(),
                package_products,
                fact_rows,
            },
        );
    }
    if order != SETUPS {
        errors.push(format!(
            "setups are {order:?}, expected exactly {SETUPS:?} in that order"
        ));
    }

    // Expectations.
    let mut out: Vec<Expect> = Vec::new();
    let mut reviewed: BTreeSet<(String, String)> = BTreeSet::new();
    for (i, e) in tables(doc.get("expect"), "expect", &mut errors)
        .into_iter()
        .enumerate()
    {
        unknown_keys(e, &EXPECT_KEYS, &format!("expect {i}"), &mut errors);
        let setup = text(e, "setup", &format!("expect {i}"), &mut errors).to_owned();
        let advisory = text(e, "advisory", &format!("expect {i}"), &mut errors).to_owned();
        let what = format!("expect {setup} x {advisory}");
        let result = text(e, "result", &what, &mut errors).to_owned();
        if !RESULTS.contains(&result.as_str()) {
            errors.push(format!(
                "{what}: result `{result}` is not one of {RESULTS:?}"
            ));
        }
        let version = text(e, "version", &what, &mut errors);
        if !VERSION_STATES.contains(&version) {
            errors.push(format!(
                "{what}: version `{version}` is not one of {VERSION_STATES:?}"
            ));
        }
        let condition = text(e, "condition", &what, &mut errors);
        if !CONDITION_STATES.contains(&condition) {
            errors.push(format!(
                "{what}: condition `{condition}` is not one of {CONDITION_STATES:?}"
            ));
        }
        if version == "not-applicable" && condition != "not-met" {
            errors.push(format!(
                "{what}: a product that isn't there leaves its service condition not-met"
            ));
        }
        if implied(version, condition) != result {
            errors.push(format!(
                "{what}: version {version} and condition {condition} give {}, not {result}",
                implied(version, condition)
            ));
        }
        match (setups.get(&setup), corpus.entries.get(&advisory)) {
            (None, _) => errors.push(format!("{what}: setup is not listed")),
            (_, None) => errors.push(format!("{what}: advisory is not in advisories/corpus/")),
            (Some(s), Some(entries)) => {
                // Does any affected entry that applies to this setup name a
                // package of a product the setup has?
                let mut mapped = false;
                for entry in entries {
                    let applies = match &entry.platform {
                        None => true,
                        Some(p) => scope_applies(p, &s.arch, &s.storage).unwrap_or(true),
                    };
                    mapped |= applies && s.packages.contains(&entry.package);
                }
                let ranged = version == "in-range" || version == "out-of-range";
                if ranged && !mapped {
                    errors.push(format!(
                        "{what}: a version call needs an affected package that maps to a product in the setup"
                    ));
                }
                if version == "not-applicable" && mapped {
                    errors.push(format!(
                        "{what}: a product in the setup has this advisory's package, so not-applicable is wrong"
                    ));
                }
                // Facts and expectations must not disagree silently: every
                // required condition of an advisory whose product runs here
                // has a fact row, unless the pair's condition is unknown.
                // service_running is carried by the services list, and
                // package_installed by the setup's package entries.
                // The condition label must equal what the setup says about
                // the required conditions: any false is not-met, otherwise
                // any unknown (no row, or a row saying unknown) is unknown,
                // otherwise met.
                let undisclosed = UNDISCLOSED_CONDITIONS.contains(&advisory.as_str());
                if mapped && !undisclosed {
                    let values: Vec<Option<bool>> = corpus
                        .required
                        .get(&advisory)
                        .into_iter()
                        .flatten()
                        .map(|r| condition_value(r, s, &alias_to_id))
                        .collect();
                    let said = if values.contains(&Some(false)) {
                        "not-met"
                    } else if values.contains(&None) {
                        "unknown"
                    } else {
                        "met"
                    };
                    if said != condition {
                        errors.push(format!(
                            "{what}: condition is {condition} but the setup's facts say {said}"
                        ));
                    }
                }
                // The vendor withheld these conditions: in range the pair is
                // possibly-affected with condition unknown; out of range the
                // condition is never not-met.
                if mapped && undisclosed {
                    let bad = match version {
                        "in-range" => condition != "unknown" || result != "possibly-affected",
                        "out-of-range" => condition == "not-met",
                        _ => false,
                    };
                    if bad {
                        errors.push(format!(
                            "{what}: the vendor withheld this advisory's conditions: in range it is possibly-affected with condition unknown, out of range the condition is never not-met"
                        ));
                    }
                }
                if mapped && condition != "unknown" {
                    for req in corpus.required.get(&advisory).into_iter().flatten() {
                        let carried = req.name == "service_running"
                            || req.name == "chain"
                            || (req.name == "package_installed" && s.has_packages);
                        let has_fact = s.facts.iter().any(|(n, sub)| {
                            *n == req.name && (req.subject.is_none() || *sub == req.subject)
                        });
                        if !carried && !has_fact {
                            errors.push(format!(
                                "{what}: required condition {} {:?} has no [[setup.fact]] and the pair's condition is not unknown",
                                req.name, req.subject
                            ));
                        }
                    }
                }
            }
        }
        text(e, "reason", &what, &mut errors);
        match (result.as_str(), e.get("question")) {
            ("possibly-affected", Some(_)) => {
                if !text(e, "question", &what, &mut errors).ends_with('?') {
                    errors.push(format!("{what}: the question must end with `?`"));
                }
            }
            ("possibly-affected", None) => errors.push(format!(
                "{what}: possibly-affected needs the question that settles it"
            )),
            (_, Some(_)) => {
                if e.get("review").is_none() {
                    errors.push(format!(
                        "{what}: only possibly-affected, or a pair marked review, has a question"
                    ));
                } else if !text(e, "question", &what, &mut errors).ends_with('?') {
                    errors.push(format!("{what}: the question must end with `?`"));
                }
            }
            (_, None) => {}
        }
        if let Some(r) = e.get("review") {
            if r.as_str() == Some("max") {
                reviewed.insert((setup.clone(), advisory.clone()));
            } else {
                errors.push(format!("{what}: review, when present, must be \"max\""));
            }
        }
        if let Some(prev) = out.last()
            && (prev.setup.as_str(), prev.advisory.as_str()) >= (setup.as_str(), advisory.as_str())
        {
            errors.push(format!(
                "{what}: entries must be sorted by setup then advisory, each pair once"
            ));
        }
        out.push(Expect {
            setup,
            advisory,
            result,
        });
    }
    let pinned: BTreeSet<(String, String)> = REVIEW_PAIRS
        .iter()
        .map(|(a, b)| ((*a).to_owned(), (*b).to_owned()))
        .collect();
    if reviewed != pinned {
        errors.push(format!(
            "the pairs marked review = \"max\" are {reviewed:?}, but REVIEW_PAIRS in the test says {pinned:?}"
        ));
    }
    for id in &order {
        let have: BTreeSet<&str> = out
            .iter()
            .filter(|e| &e.setup == id)
            .map(|e| e.advisory.as_str())
            .collect();
        for missing in corpus.entries.keys() {
            if !have.contains(missing.as_str()) {
                errors.push(format!("setup {id}: no expectation for advisory {missing}"));
            }
        }
    }
    if errors.is_empty() {
        Ok(out)
    } else {
        Err(errors)
    }
}

fn load() -> Vec<Expect> {
    check(&read(FILE), &corpus(), &lab_versions())
        .unwrap_or_else(|errs| panic!("{FILE} has problems:\n  {}", errs.join("\n  ")))
}

fn count(expects: &[Expect], result: &str) -> usize {
    expects.iter().filter(|e| e.result == result).count()
}

#[derive(Debug, PartialEq, Eq)]
struct Score {
    expected_alerts: usize,
    reported: usize,
    correct: usize,
}

impl Score {
    fn percent(n: usize, d: usize) -> String {
        (n * 100)
            .checked_div(d)
            .map_or_else(|| "n/a".to_owned(), |p| format!("{p}%"))
    }
    fn line(&self) -> String {
        format!(
            "reported {}, correct {}; precision {} ({} of {}), recall {} ({} of {})",
            self.reported,
            self.correct,
            Self::percent(self.correct, self.reported),
            self.correct,
            self.reported,
            Self::percent(self.correct, self.expected_alerts),
            self.correct,
            self.expected_alerts,
        )
    }
}

/// Precision and recall over alerts. The matcher gets only the setup and
/// advisory ids, and answers `Some(result)` to raise an alert (affected or
/// possibly-affected) or `None` to say nothing (its way of saying
/// not-affected). An alert is correct only when its result is exactly the
/// expected one.
fn score(expects: &[Expect], matcher: &dyn Fn(MatchInput<'_>) -> Option<&'static str>) -> Score {
    let mut s = Score {
        expected_alerts: 0,
        reported: 0,
        correct: 0,
    };
    for e in expects {
        let expected = (e.result != "not-affected").then_some(e.result.as_str());
        let got = matcher(MatchInput {
            setup: &e.setup,
            advisory: &e.advisory,
        })
        .filter(|r| *r != "not-affected");
        s.expected_alerts += usize::from(expected.is_some());
        s.reported += usize::from(got.is_some());
        s.correct += usize::from(got.is_some() && got == expected);
    }
    s
}

/// Phase 2 replaces this with the real matcher.
fn no_matcher_yet(_: MatchInput<'_>) -> Option<&'static str> {
    None
}

#[test]
fn expected_matches_cover_every_setup_and_advisory() {
    let expects = load();
    assert_eq!(expects.len(), SETUPS.len() * corpus().entries.len());
    for setup in SETUPS {
        let mine: Vec<Expect> = expects
            .iter()
            .filter(|e| e.setup == setup)
            .cloned()
            .collect();
        eprintln!(
            "{setup}: affected {}, not-affected {}, possibly-affected {}",
            count(&mine, "affected"),
            count(&mine, "not-affected"),
            count(&mine, "possibly-affected")
        );
    }
    assert!(
        count(&expects, "affected") > 0,
        "at least one setup must exercise affected"
    );
}

#[test]
fn every_platform_scope_is_understood() {
    let c = corpus();
    let used: BTreeSet<&str> = c
        .entries
        .values()
        .flatten()
        .filter_map(|e| e.platform.as_deref())
        .collect();
    let known: BTreeSet<&str> = PLATFORM_SCOPES.iter().map(|(name, _)| *name).collect();
    assert_eq!(
        used, known,
        "every per-entry database_specific.platform in the corpus needs a rule in PLATFORM_SCOPES"
    );
    assert_eq!(
        scope_applies(PLATFORM_SCOPES[0].0, "64-bit", "tmpfs"),
        Some(true)
    );
    assert_eq!(
        scope_applies(PLATFORM_SCOPES[1].0, "64-bit", "tmpfs"),
        Some(false)
    );
    assert_eq!(
        scope_applies(PLATFORM_SCOPES[1].0, "64-bit", "fat32"),
        Some(true)
    );
    assert_eq!(
        scope_applies(PLATFORM_SCOPES[1].0, "32-bit", "ext4"),
        Some(true)
    );
}

#[test]
fn judge_b_matcher_baseline() {
    let expects = load();
    let s = score(&expects, &no_matcher_yet);
    eprintln!("Judge B, no matcher yet: {}", s.line());
    // The recorded baseline (tests/README.md). Update both when the matcher lands.
    assert_eq!(
        s,
        Score {
            expected_alerts: 9,
            reported: 0,
            correct: 0
        }
    );
}

#[test]
fn the_scoring_has_teeth() {
    let expects = load();
    let answers: BTreeMap<(String, String), &'static str> = expects
        .iter()
        .map(|e| {
            let r = RESULTS.iter().copied().find(|r| *r == e.result).unwrap();
            ((e.setup.clone(), e.advisory.clone()), r)
        })
        .collect();
    let oracle = |m: MatchInput<'_>| {
        answers
            .get(&(m.setup.to_owned(), m.advisory.to_owned()))
            .copied()
    };
    let perfect = score(&expects, &oracle);
    assert_eq!(perfect.correct, perfect.reported);
    assert_eq!(perfect.correct, perfect.expected_alerts);
    let loud = score(&expects, &|_| Some("affected"));
    assert_eq!(
        (loud.reported, loud.correct),
        (expects.len(), count(&expects, "affected"))
    );
    let hedge = score(&expects, &|_| Some("possibly-affected"));
    assert_eq!(
        (hedge.reported, hedge.correct),
        (expects.len(), count(&expects, "possibly-affected"))
    );
}

/// Which setup the text at byte `at` belongs to: the nearest `[[setup]]` id or
/// `[[expect]]` setup line before it ("" before the first setup).
fn anchor_setup(file: &str, at: usize) -> String {
    let before = &file[..at];
    let a = before.rfind("[[setup]]\nid = \"");
    let b = before.rfind("[[expect]]\nsetup = \"");
    let (pos, skip) = match (a, b) {
        (Some(a), Some(b)) if b > a => (b, "[[expect]]\nsetup = \"".len()),
        (Some(a), _) => (a, "[[setup]]\nid = \"".len()),
        (None, Some(b)) => (b, "[[expect]]\nsetup = \"".len()),
        (None, None) => return String::new(),
    };
    before[pos + skip..].split('"').next().unwrap().to_owned()
}

#[test]
fn an_unknown_chain_name_in_the_corpus_is_refused() {
    let mut c = corpus();
    let cond = c
        .conditions
        .iter_mut()
        .find(|c| c.name == "chain")
        .expect("the corpus has a chain condition");
    cond.any_of.as_mut().unwrap().push("testnet".to_owned());
    let errs = check(&read(FILE), &c, &lab_versions()).expect_err("a typo'd chain was accepted");
    assert!(
        errs.iter().any(|e| e.contains("`testnet`, not one of")),
        "got:\n  {}",
        errs.join("\n  ")
    );
}

#[test]
fn every_broken_file_is_refused() {
    let good = read(FILE);
    let c = corpus();
    let lab = lab_versions();
    let first = "advisory = \"CVE-2024-35202\"\nresult = \"not-affected\"";
    let cases: &[(&str, &str, &str, &str, &str)] = &[
        (
            "unknown result",
            "lab-old-synthetic",
            first,
            "advisory = \"CVE-2024-35202\"\nresult = \"safe\"",
            "is not one of",
        ),
        (
            "result disagrees with the calls",
            "lab-old-synthetic",
            first,
            "advisory = \"CVE-2024-35202\"\nresult = \"affected\"",
            "give not-affected",
        ),
        (
            "unknown advisory",
            "lab-old-synthetic",
            "advisory = \"CVE-2024-35202\"",
            "advisory = \"CVE-2099-0001\"",
            "not in advisories/corpus",
        ),
        (
            "duplicate pair",
            "lab-old-synthetic",
            "advisory = \"CVE-2024-38359\"",
            "advisory = \"CVE-2024-35202\"",
            "each pair once",
        ),
        (
            "missing pair",
            "lab-old-synthetic",
            "advisory = \"CVE-2024-38359\"",
            "advisory = \"CVE-2024-38359x\"",
            "no expectation for advisory CVE-2024-38359",
        ),
        (
            "unlisted setup",
            "lab-old-synthetic",
            "setup = \"lab-old-synthetic\"\nadvisory = \"CVE-2024-35202\"",
            "setup = \"lab-other\"\nadvisory = \"CVE-2024-35202\"",
            "setup is not listed",
        ),
        (
            "possibly without a question",
            "lab-old-synthetic",
            "question = \"Which xz-utils",
            "#question = \"Which xz-utils",
            "needs the question",
        ),
        (
            "question without a question mark",
            "lab-old-synthetic",
            "services run?\"",
            "services run\"",
            "must end with `?`",
        ),
        (
            "question on a not-affected pair",
            "lab-old-synthetic",
            first,
            "question = \"Why?\"\nadvisory = \"CVE-2024-35202\"\nresult = \"not-affected\"",
            "only possibly-affected",
        ),
        (
            "empty reason",
            "lab-old-synthetic",
            "reason = \"Bitcoin Core 28.1 is not below the fix 25.0 (range 0 to fixed 25.0).\"",
            "reason = \"\"",
            "`reason` must be one line",
        ),
        (
            "reason with a control character",
            "lab-old-synthetic",
            "fix 25.0 (range",
            "fix 25.0\\u001b(range",
            "`reason` must be one line",
        ),
        (
            "review other than max",
            "lab-old-synthetic",
            "\nreview = \"max\"",
            "\nreview = \"someone\"",
            "must be \"max\"",
        ),
        (
            "unknown key",
            "lab-old-synthetic",
            first,
            "severity = \"high\"\nadvisory = \"CVE-2024-35202\"\nresult = \"not-affected\"",
            "unknown key `severity`",
        ),
        (
            "a version that isn't the lab's",
            "lab-regtest",
            "version = \"32.1\"",
            "version = \"32.0\"",
            "differ from the lab's pinned images",
        ),
        (
            "a service the lab doesn't run",
            "lab-regtest",
            "id = \"strfry\"\nversion",
            "id = \"tapd\"\nversion",
            "differ from the lab's pinned images",
        ),
        (
            "absent product with condition met",
            "lab-old-synthetic",
            "version = \"not-applicable\"\ncondition = \"not-met\"",
            "version = \"not-applicable\"\ncondition = \"met\"",
            "leaves its service condition not-met",
        ),
        (
            "wrong format",
            "",
            "format = 1",
            "format = 2",
            "`format` must be 1",
        ),
        (
            "a version call with no matching package",
            "",
            "packages = [\"Go github.com/lightningnetwork/lnd\"]",
            "packages = [\"Go example.org/other\"]",
            "needs an affected package that maps",
        ),
        (
            "not-applicable for a product that is there",
            "lab-old-synthetic",
            "advisory = \"CVE-2024-38359\"\nresult = \"not-affected\"\nversion = \"out-of-range\"\ncondition = \"met\"",
            "advisory = \"CVE-2024-38359\"\nresult = \"not-affected\"\nversion = \"not-applicable\"\ncondition = \"not-met\"",
            "not-applicable is wrong",
        ),
        (
            "a condition service with no product",
            "",
            "aliases = [\"cashu-nutshell-mint\"]",
            "aliases = []",
            "`cashu-nutshell-mint` in the corpus is not a known product",
        ),
        (
            "a synthetic setup not labelled",
            "lab-old-synthetic",
            "description = \"SYNTHETIC, not",
            "description = \"Old, not",
            "must start with SYNTHETIC",
        ),
        (
            "package versions without their evidence",
            "lab-regtest",
            "packages_from = \"2026-11-16:",
            "#packages_from = \"2026-11-16:",
            "need `packages_from`",
        ),
        (
            "an unknown arch",
            "lab-old-synthetic",
            "arch = \"64-bit\"",
            "arch = \"arm\"",
            "is not one of",
        ),
        (
            "an unknown fact key",
            "lab-old-synthetic",
            "[[setup.fact]]\nname = \"p2p_inbound_or_outbound_peers\"",
            "[[setup.fact]]\nseverity = \"high\"\nname = \"p2p_inbound_or_outbound_peers\"",
            "unknown key `severity`",
        ),
        (
            "an unknown fact name",
            "lab-old-synthetic",
            "name = \"node_builds_block_templates\"",
            "name = \"node_builds_blocks\"",
            "is not a condition name used in advisories/corpus",
        ),
        (
            "a fact service not in the setup",
            "lab-old-synthetic",
            "service = \"lnd\"\nsubject = \"nobootstrap\"",
            "service = \"strfry\"\nsubject = \"nobootstrap\"",
            "is not a service in this setup",
        ),
        (
            "a bad fact value",
            "lab-old-synthetic",
            "name = \"p2p_inbound_or_outbound_peers\"\nservice = \"bitcoin-core\"\nvalue = \"false\"",
            "name = \"p2p_inbound_or_outbound_peers\"\nservice = \"bitcoin-core\"\nvalue = \"maybe\"",
            "value `maybe` is not one of",
        ),
        (
            "a subject on a fact without an argument",
            "lab-old-synthetic",
            "name = \"p2p_inbound_or_outbound_peers\"\nservice",
            "name = \"p2p_inbound_or_outbound_peers\"\nsubject = \"x\"\nservice",
            "only a fact with an argument has a `subject`",
        ),
        (
            "fact evidence naming a local path",
            "lab-old-synthetic",
            "evidence = \"description: ",
            "evidence = \"/srv/lab: ",
            "evidence names a local path",
        ),
        (
            "a required condition with no fact",
            "lab-old-synthetic",
            "name = \"node_builds_block_templates\"",
            "name = \"accepts_inbound_p2p\"",
            "required condition node_builds_block_templates",
        ),
        (
            "a required condition with no fact in the lab",
            "lab-regtest",
            "name = \"option_disabled\"\nservice = \"lnd\"\nsubject = \"nobootstrap\"\nvalue = \"true\"\nevidence = \"lab/compose.yml",
            "name = \"option_disabled\"\nservice = \"lnd\"\nsubject = \"other\"\nvalue = \"true\"\nevidence = \"lab/compose.yml",
            "required condition option_disabled",
        ),
        (
            "a setup on a chain with an unknown name",
            "lab-old-synthetic",
            "chain = \"regtest\"",
            "chain = \"mainnet\"",
            "chain `mainnet` is not one of",
        ),
        (
            "a condition label that contradicts the chain (not-met chain, met label)",
            "lab-old-synthetic",
            "result = \"not-affected\"\nversion = \"in-range\"\ncondition = \"not-met\"\nreason = \"LND 0.18.4-beta is below the fix 0.20.2-beta",
            "result = \"affected\"\nversion = \"in-range\"\ncondition = \"met\"\nreason = \"LND 0.18.4-beta is below the fix 0.20.2-beta",
            "but the setup's facts say not-met",
        ),
        (
            "a condition label that contradicts the chain in the lab",
            "lab-regtest",
            "result = \"not-affected\"\nversion = \"out-of-range\"\ncondition = \"not-met\"\nreason = \"LND 0.21.6-beta is in neither",
            "result = \"not-affected\"\nversion = \"out-of-range\"\ncondition = \"met\"\nreason = \"LND 0.21.6-beta is in neither",
            "but the setup's facts say not-met",
        ),
        (
            "an unknown fact with a met label",
            "lab-old-synthetic",
            "name = \"node_builds_block_templates\"\nservice = \"bitcoin-core\"\nvalue = \"true\"",
            "name = \"node_builds_block_templates\"\nservice = \"bitcoin-core\"\nvalue = \"unknown\"",
            "but the setup's facts say unknown",
        ),
        (
            "an unknown fact with a not-met label",
            "lab-old-synthetic",
            "name = \"p2p_inbound_or_outbound_peers\"\nservice = \"bitcoin-core\"\nvalue = \"false\"",
            "name = \"p2p_inbound_or_outbound_peers\"\nservice = \"bitcoin-core\"\nvalue = \"unknown\"",
            "but the setup's facts say unknown",
        ),
        (
            "the nobootstrap row moved to another service",
            "lab-old-synthetic",
            "service = \"lnd\"\nsubject = \"nobootstrap\"",
            "service = \"bitcoin-core\"\nsubject = \"nobootstrap\"",
            "is not a service any advisory condition names for this fact",
        ),
        (
            "a tapd option row that claims a service",
            "lab-old-synthetic",
            "name = \"option_enabled\"\nsubject",
            "name = \"option_enabled\"\nservice = \"lnd\"\nsubject",
            "is not a service any advisory condition names for this fact",
        ),
        (
            "a row for an absent service with value true",
            "lab-old-synthetic",
            "subject = \"invoice HTLC interceptor (or any HtlcModifier RPC client)\"\nvalue = \"false\"",
            "subject = \"invoice HTLC interceptor (or any HtlcModifier RPC client)\"\nvalue = \"true\"",
            "with no `service` the value must be false",
        ),
        (
            "two rows for the same fact that conflict",
            "lab-old-synthetic",
            "name = \"node_builds_block_templates\"\nservice = \"bitcoin-core\"\nvalue = \"true\"",
            "name = \"p2p_inbound_or_outbound_peers\"\nservice = \"bitcoin-core\"\nvalue = \"true\"",
            "conflicting service or value",
        ),
        (
            "a row for the chain",
            "lab-old-synthetic",
            "name = \"node_builds_block_templates\"",
            "name = \"chain\"",
            "already carry this",
        ),
        (
            "the withheld-conditions pair marked not-affected",
            "lab-old-synthetic",
            "result = \"possibly-affected\"\nversion = \"in-range\"\ncondition = \"unknown\"\nreason = \"Core Lightning 25.09",
            "result = \"not-affected\"\nversion = \"in-range\"\ncondition = \"not-met\"\nreason = \"Core Lightning 25.09",
            "the vendor withheld this advisory's conditions",
        ),
        (
            "a review mark added without editing the list",
            "lab-old-synthetic",
            "reason = \"Bitcoin Core 28.1 is not below the fix 25.0 (range 0 to fixed 25.0).\"",
            "reason = \"Bitcoin Core 28.1 is not below the fix 25.0 (range 0 to fixed 25.0).\"\nreview = \"max\"",
            "REVIEW_PAIRS in the test says",
        ),
        (
            "a review mark removed without editing the list",
            "lab-regtest",
            "tmpfs).\"\nreview = \"max\"",
            "tmpfs).\"",
            "REVIEW_PAIRS in the test says",
        ),
        (
            "evidence with a home path",
            "lab-old-synthetic",
            "evidence = \"description: ",
            "evidence = \"~/ lab: ",
            "evidence names a local path",
        ),
        (
            "evidence with an environment path",
            "lab-old-synthetic",
            "evidence = \"description: ",
            "evidence = \"$HOME/lab: ",
            "evidence names a local path",
        ),
        (
            "evidence with a drive path",
            "lab-old-synthetic",
            "evidence = \"description: ",
            "evidence = \"C:\\\\lab: ",
            "evidence names a local path",
        ),
        (
            "evidence with an absolute path in the middle",
            "lab-old-synthetic",
            "evidence = \"description: ",
            "evidence = \"description see /srv/lab for ",
            "evidence names a local path",
        ),
        (
            "empty evidence",
            "lab-regtest",
            "evidence = \"lab/compose.yml: the lnd command line",
            "evidence = \"\"\nignored = \"lab/compose.yml: the lnd command line",
            "`evidence` must be one line",
        ),
    ];
    for &(name, owner, from, to, want) in cases {
        let at = good
            .find(from)
            .unwrap_or_else(|| panic!("{name}: anchor `{from}` not found"));
        assert_eq!(
            anchor_setup(&good, at),
            owner,
            "{name}: the anchor lands in the wrong setup"
        );
        let bad = good.replacen(from, to, 1);
        match check(&bad, &c, &lab) {
            Ok(_) => panic!("{name}: the broken file was accepted"),
            Err(errs) => assert!(
                errs.iter().any(|e| e.contains(want)),
                "{name}: expected a problem containing `{want}`, got:\n  {}",
                errs.join("\n  ")
            ),
        }
    }
}
