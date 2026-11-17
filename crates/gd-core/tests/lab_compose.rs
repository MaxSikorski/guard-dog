//! The regtest lab's compose file and scripts (Phase 0.8), checked without
//! starting Docker.
//!
//! Deterministic by design: no Docker, no network, no clock, nothing random.
//! `check()` reads `lab/compose.yml` the way Docker does (the file uses no YAML
//! anchors) and returns every problem it finds, in a stable order. The checker
//! is itself tested: `every_unsafe_change_is_caught` makes 37 named unsafe
//! edits and requires each one to be refused with its own problem code.

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

use std::collections::BTreeSet;
use std::fs;
use std::path::{Path, PathBuf};

use yaml_rust2::{Yaml, YamlLoader};

/// The compose project name.
const PROJECT: &str = "gd-lab";
/// The lab network's only subnet.
const SUBNET: &str = "172.29.208.0/24";
/// Total memory budget for the lab, in MiB (plan 0.8: under 4 GB).
const MEMORY_BUDGET_MIB: u64 = 4096;
/// Every reviewed service: (compose name, Judge A id, exact image, expected version, user).
const EXPECTED: [(&str, &str, &str, &str, &str); 5] = [
    (
        "bitcoind",
        "bitcoin-core",
        "bitcoin/bitcoin@sha256:d2454aaf2ff4ce1ebbc49f4aa05ed044c907b849a80a3f4c0ad23e488e50bbe0",
        "32.1",
        "101:101",
    ),
    (
        "cln",
        "core-lightning",
        "elementsproject/lightningd@sha256:de74289ddcccb68cd60543b08b2b8594002d819125d200492e17a95166d56577",
        "26.06.9",
        "1000:1000",
    ),
    (
        "lnd",
        "lnd",
        "lightninglabs/lnd@sha256:54b3c87ad0bc3fea3fab8af23ace6421147ea97e6b56bf3911592d7853c185b8",
        "0.21.6-beta",
        "1000:1000",
    ),
    (
        "nutshell",
        "nutshell",
        "cashubtc/nutshell@sha256:beed25e291357368e35e1698bf2e4645d97ed435232a8f8ff6501c77d67c0b90",
        "0.21.0",
        "1000:1000",
    ),
    (
        "strfry",
        "strfry",
        "ghcr.io/hoytech/strfry@sha256:36f1886d185a88ca57c66ebe52e6e9e8428dac2486eea0a5d50ff934f18b60c3",
        "1.1.2-148-g4cd3cf6",
        "1000:1000",
    ),
];
/// The only keys a lab service may use.
const ALLOWED_SERVICE_KEYS: [&str; 20] = [
    "image",
    "labels",
    "user",
    "entrypoint",
    "command",
    "environment",
    "working_dir",
    "depends_on",
    "healthcheck",
    "tmpfs",
    "networks",
    "read_only",
    "cap_drop",
    "security_opt",
    "init",
    "restart",
    "mem_limit",
    "memswap_limit",
    "cpus",
    "pids_limit",
];
/// Keys that have their own problem code, so they never also count as `unknown-key`.
const SPECIFIC_KEYS: [&str; 12] = [
    "ports",
    "expose",
    "privileged",
    "cap_add",
    "volumes",
    "network_mode",
    "pid",
    "ipc",
    "uts",
    "userns_mode",
    "cgroup",
    "devices",
];
/// Words that mark a name as holding a secret.
const SECRET_WORDS: [&str; 7] = [
    "pass",
    "rpcauth",
    "secret",
    "private_key",
    "token",
    "rune",
    "macaroon",
];
/// What a generated credential starts with (see `lab/up.sh`).
const CANARY: &str = "gdlabcanary-";

/// The reviewed `entrypoint` per service; `None` means it must be absent.
const ENTRYPOINTS: [(&str, Option<&str>); 5] = [
    ("bitcoind", Some("bitcoind")),
    ("cln", None),
    ("lnd", None),
    ("nutshell", None),
    ("strfry", None),
];
/// Every tmpfs mount each service must have, and no others.
const TMPFS_TARGETS: [(&str, &[&str]); 5] = [
    ("bitcoind", &["/data", "/home/bitcoin/.bitcoin"]),
    ("cln", &["/data", "/tmp", "/root/.lightning"]),
    ("lnd", &["/data", "/root/.lnd"]),
    ("nutshell", &["/data", "/tmp"]),
    ("strfry", &["/data"]),
];
/// The smallest memory limit that can run anything at all, in MiB.
const MIN_MEM_MIB: u64 = 6;

/// A command line as named options: leading dashes removed, with the value
/// either after `=` or in the next item (unless that item is another option).
/// So `-x=v`, `--x=v` and `--x v` all read as ("x", Some("v")).
fn options(items: &[String]) -> Vec<(String, Option<String>)> {
    let mut out = Vec::new();
    let mut i = 0;
    while i < items.len() {
        let item = &items[i];
        i += 1;
        if !item.starts_with('-') {
            continue;
        }
        let body = item.trim_start_matches('-');
        if let Some((name, value)) = body.split_once('=') {
            out.push((name.to_owned(), Some(value.to_owned())));
        } else if i < items.len() && !items[i].starts_with('-') {
            out.push((body.to_owned(), Some(items[i].clone())));
            i += 1;
        } else {
            out.push((body.to_owned(), None));
        }
    }
    out
}

/// Chain selectors in a command line: every option whose name is in `names`.
/// Returns true if there is exactly one and it names regtest (`ok_value`
/// matches its value; a bare option counts as the value `""`).
fn single_regtest_selector(
    items: &[String],
    names: &[&str],
    ok: impl Fn(&str, &str) -> bool,
) -> bool {
    let found: Vec<_> = options(items)
        .into_iter()
        .filter(|(n, _)| names.contains(&n.as_str()))
        .collect();
    found.len() == 1 && ok(&found[0].0, found[0].1.as_deref().unwrap_or(""))
}

/// One thing wrong with the compose file.
struct Problem {
    /// A short stable name for the kind of problem.
    code: &'static str,
    /// What exactly was found.
    detail: String,
}

fn root() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../..")
}

fn read(rel: &str) -> String {
    let path = root().join(rel);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display()))
}

/// The keys of a mapping, as strings (non-string keys are skipped).
fn keys(y: &Yaml) -> Vec<String> {
    y.as_hash()
        .map(|h| {
            h.keys()
                .filter_map(|k| k.as_str().map(str::to_owned))
                .collect()
        })
        .unwrap_or_default()
}

/// A list of strings, or `None` if it isn't one.
fn strings(y: &Yaml) -> Option<Vec<String>> {
    y.as_vec()?
        .iter()
        .map(|v| v.as_str().map(str::to_owned))
        .collect()
}

/// Whether any string anywhere under `y` (keys included) contains `needle`.
fn any_string_contains(y: &Yaml, needle: &str) -> bool {
    match y {
        Yaml::String(s) => s.contains(needle),
        Yaml::Array(a) => a.iter().any(|v| any_string_contains(v, needle)),
        Yaml::Hash(h) => h
            .iter()
            .any(|(k, v)| any_string_contains(k, needle) || any_string_contains(v, needle)),
        _ => false,
    }
}

/// `512m` or `4g` as MiB.
fn mem_mib(s: &str) -> Option<u64> {
    let (digits, unit) = s.split_at(s.len().checked_sub(1)?);
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let n: u64 = digits.parse().ok()?;
    match unit {
        "m" => Some(n),
        "g" => Some(n * 1024),
        _ => None,
    }
}

/// A value for a secret-looking name must be a `${GD_LAB_...:?...}` reference.
fn is_lab_reference(v: &str) -> bool {
    v.starts_with("${GD_LAB_") && v.ends_with('}') && v.contains(":?")
}

fn has_secret_word(name: &str) -> bool {
    let lower = name.to_lowercase();
    SECRET_WORDS.iter().any(|w| lower.contains(w))
}

/// Whether the text holds `gdlabcanary-` followed by at least 8 hex digits.
fn has_canary(text: &str) -> bool {
    text.match_indices(CANARY).any(|(i, _)| {
        text[i + CANARY.len()..]
            .bytes()
            .take_while(u8::is_ascii_hexdigit)
            .count()
            >= 8
    })
}

/// A pinned image is `name@sha256:` plus exactly 64 lowercase hex digits.
fn is_pinned(image: &str) -> bool {
    match image.split_once("@sha256:") {
        Some((_, hex)) => {
            hex.len() == 64
                && hex
                    .bytes()
                    .all(|b| b.is_ascii_digit() || (b'a'..=b'f').contains(&b))
        }
        None => false,
    }
}

/// Every problem in a compose file's text, never stopping at the first. The
/// order is stable: top level, then services in `EXPECTED` order, then totals.
fn check(text: &str) -> Vec<Problem> {
    let mut out = Vec::new();
    let docs = match YamlLoader::load_from_str(text) {
        Ok(d) => d,
        Err(e) => {
            out.push(problem("unparseable", format!("{e}")));
            return out;
        }
    };
    let [doc] = docs.as_slice() else {
        out.push(problem(
            "unparseable",
            format!("{} YAML documents, expected 1", docs.len()),
        ));
        return out;
    };
    if doc.as_hash().is_none() {
        out.push(problem("unparseable", "the root is not a mapping".into()));
        return out;
    }

    // Top level.
    let top = keys(doc);
    for want in ["name", "services", "networks"] {
        if !top.iter().any(|k| k == want) {
            out.push(problem(
                "top-level",
                format!("missing top-level key {want}"),
            ));
        }
    }
    for k in &top {
        if k == "volumes" {
            out.push(problem(
                "named-volume",
                "a top-level volumes key exists".into(),
            ));
        } else if !["name", "services", "networks"].contains(&k.as_str()) {
            out.push(problem(
                "top-level",
                format!("unexpected top-level key {k}"),
            ));
        }
    }
    if doc["name"].as_str() != Some(PROJECT) {
        out.push(problem(
            "top-level",
            format!("name must be {PROJECT}, found {:?}", doc["name"]),
        ));
    }

    // The set of services.
    let services = &doc["services"];
    let names: BTreeSet<String> = keys(services).into_iter().collect();
    let want: BTreeSet<String> = EXPECTED.iter().map(|e| e.0.to_owned()).collect();
    if names != want {
        out.push(problem(
            "unexpected-services",
            format!("services are {names:?}, expected {want:?}"),
        ));
    }

    // Each reviewed service, in order.
    let mut total_mib = 0;
    for (name, id, image, version, user) in EXPECTED {
        let svc = &services[name];
        if svc.as_hash().is_none() {
            continue;
        }
        check_service(&mut out, name, id, image, version, user, svc);
        if let Some(m) = svc["mem_limit"].as_str().and_then(mem_mib) {
            total_mib += m;
        }
    }

    // The network.
    let nets = &doc["networks"];
    let lab = &nets["lab"];
    if lab["internal"].as_bool() != Some(true) {
        out.push(problem(
            "network-not-internal",
            "networks.lab must have internal: true".into(),
        ));
    }
    let mut lab_keys = keys(lab);
    lab_keys.sort();
    let ipam_keys = keys(&lab["ipam"]);
    let entries = lab["ipam"]["config"].as_vec();
    let entry_keys_ok = entries.is_some_and(|c| c.iter().all(|e| keys(e) == ["subnet"]));
    if keys(nets) != ["lab"]
        || lab_keys != ["driver", "driver_opts", "internal", "ipam"]
        || ipam_keys != ["config"]
        || !entry_keys_ok
    {
        out.push(problem(
            "network-keys",
            "networks must be exactly lab: {internal, driver, driver_opts, ipam: {config: [{subnet}]}}"
                .into(),
        ));
    }
    let opts = &lab["driver_opts"];
    if lab["driver"].as_str() != Some("bridge")
        || keys(opts) != ["com.docker.network.bridge.gateway_mode_ipv4"]
        || opts["com.docker.network.bridge.gateway_mode_ipv4"].as_str() != Some("isolated")
    {
        out.push(problem(
            "network-not-isolated",
            "networks.lab needs driver: bridge and gateway_mode_ipv4: isolated".into(),
        ));
    }
    let one_subnet =
        entries.is_some_and(|c| c.len() == 1 && c[0]["subnet"].as_str() == Some(SUBNET));
    if !one_subnet {
        out.push(problem(
            "wrong-subnet",
            format!("networks.lab.ipam.config must be the one subnet {SUBNET}"),
        ));
    }

    // Anywhere in the file, a generated-looking credential.
    if has_canary(text) {
        out.push(problem(
            "literal-secret",
            format!("the file contains a {CANARY}... credential"),
        ));
    }

    if total_mib > MEMORY_BUDGET_MIB {
        out.push(problem(
            "memory-over-budget",
            format!("memory limits add up to {total_mib} MiB, over {MEMORY_BUDGET_MIB}"),
        ));
    }
    out
}

fn problem(code: &'static str, detail: String) -> Problem {
    Problem { code, detail }
}

/// The checks that apply to one service.
fn check_service(
    out: &mut Vec<Problem>,
    name: &str,
    id: &str,
    image: &str,
    version: &str,
    user: &str,
    svc: &Yaml,
) {
    let mut add = |code: &'static str, detail: String| {
        out.push(problem(code, format!("{name}: {detail}")));
    };

    // Image.
    let found = svc["image"].as_str().unwrap_or("");
    if !is_pinned(found) {
        add(
            "unpinned-image",
            format!("image {found:?} is not name@sha256:<64 hex>"),
        );
    } else if found != image {
        add(
            "wrong-image",
            format!("image {found:?} is not the reviewed one"),
        );
    }

    // Labels.
    let labels = &svc["labels"];
    let mut label_keys = keys(labels);
    label_keys.sort();
    let mut want_keys = [
        "org.guard-dog.lab.service",
        "org.guard-dog.lab.id",
        "org.guard-dog.lab.software",
        "org.guard-dog.lab.expected-version",
    ]
    .map(str::to_owned);
    want_keys.sort();
    let software_ok = labels["org.guard-dog.lab.software"]
        .as_str()
        .is_some_and(|s| !s.is_empty());
    if label_keys != want_keys
        || labels["org.guard-dog.lab.service"].as_str() != Some(name)
        || labels["org.guard-dog.lab.id"].as_str() != Some(id)
        || labels["org.guard-dog.lab.expected-version"].as_str() != Some(version)
        || !software_ok
    {
        add(
            "wrong-labels",
            format!("labels must be the four org.guard-dog.lab.* keys for {id} {version}"),
        );
    }

    // Who it runs as.
    let found_user = svc["user"].as_str().unwrap_or("");
    let rooty = found_user
        .split(':')
        .any(|part| part == "0" || part == "root");
    if found_user != user || rooty {
        add(
            "root-user",
            format!("user is {found_user:?}, expected {user:?}"),
        );
    }

    // Lock-down.
    if svc["read_only"].as_bool() != Some(true) {
        add("writable-root", "read_only is not true".into());
    }
    if strings(&svc["cap_drop"]).as_deref() != Some(&["ALL".to_owned()]) {
        add("capabilities-not-dropped", "cap_drop is not [ALL]".into());
    }
    if strings(&svc["security_opt"]).as_deref() != Some(&["no-new-privileges:true".to_owned()]) {
        add(
            "privileges-not-locked",
            "security_opt must be exactly [no-new-privileges:true]".into(),
        );
    }
    if svc["restart"].as_str() != Some("no") || svc["init"].as_bool() != Some(true) {
        add(
            "restart-or-init",
            "needs restart: \"no\" and init: true".into(),
        );
    }

    // Things a lab service must never have.
    let has = |k: &str| keys(svc).iter().any(|x| x == k);
    if has("ports") || has("expose") {
        add("host-port", "ports or expose is set".into());
    }
    if has("privileged") {
        add("privileged", "privileged is set".into());
    }
    if has("cap_add") {
        add("capability-added", "cap_add is set".into());
    }
    if has("volumes") || any_string_contains(svc, "docker.sock") {
        add("host-mount", "volumes or the Docker socket".into());
    }
    for k in ["network_mode", "pid", "ipc", "uts", "userns_mode", "cgroup"] {
        if has(k) {
            add("host-namespace", format!("{k} is set"));
        }
    }
    if has("devices") {
        add("host-device", "devices is set".into());
    }
    for k in keys(svc) {
        if !ALLOWED_SERVICE_KEYS.contains(&k.as_str()) && !SPECIFIC_KEYS.contains(&k.as_str()) {
            add("unknown-key", format!("key {k} is not allowed"));
        }
    }

    // Network and limits.
    if strings(&svc["networks"]).as_deref() != Some(&["lab".to_owned()]) {
        add("wrong-network", "networks is not [lab]".into());
    }
    let mem = svc["mem_limit"].as_str();
    if !mem.and_then(mem_mib).is_some_and(|m| m >= MIN_MEM_MIB) {
        add(
            "no-memory-limit",
            "mem_limit is missing, not like 512m, or under 6 MiB".into(),
        );
    }
    if mem.is_none() || svc["memswap_limit"].as_str() != mem {
        add(
            "swap-not-capped",
            "memswap_limit must equal mem_limit".into(),
        );
    }
    let cpus = match &svc["cpus"] {
        Yaml::Real(s) => s.parse::<f64>().ok(),
        Yaml::Integer(i) => Some(*i as f64),
        _ => None,
    };
    if !cpus.is_some_and(|c| c > 0.0 && c <= 2.0) {
        add(
            "no-cpu-limit",
            "cpus must be above 0 and at most 2.0".into(),
        );
    }
    if !svc["pids_limit"]
        .as_i64()
        .is_some_and(|p| (1..=1024).contains(&p))
    {
        add("no-pids-limit", "pids_limit must be from 1 to 1024".into());
    }
    let tmpfs_ok = strings(&svc["tmpfs"])
        .is_some_and(|v| v.iter().all(|t| t.starts_with('/') && t.contains("size=")));
    if !tmpfs_ok {
        add(
            "tmpfs-unbounded",
            "tmpfs must be a list of /path:...size=... entries".into(),
        );
    }
    let targets: Vec<String> = strings(&svc["tmpfs"])
        .unwrap_or_default()
        .iter()
        .map(|t| t.split(':').next().unwrap_or("").to_owned())
        .collect();
    let want_targets: Vec<String> = TMPFS_TARGETS
        .iter()
        .find(|t| t.0 == name)
        .map(|t| t.1.iter().map(|s| (*s).to_owned()).collect())
        .unwrap_or_default();
    if targets != want_targets {
        add(
            "tmpfs-missing",
            format!("tmpfs targets are {targets:?}, expected {want_targets:?}"),
        );
    }

    // `command` and `entrypoint` are lists of strings, and `entrypoint` is the reviewed one.
    let mut list_ok = true;
    for key in ["command", "entrypoint"] {
        if !svc[key].is_badvalue() && strings(&svc[key]).is_none() {
            list_ok = false;
            add(
                "command-not-list",
                format!("{key} must be a list of strings"),
            );
        }
    }
    let entry = strings(&svc["entrypoint"]);
    let want_entry = ENTRYPOINTS
        .iter()
        .find(|e| e.0 == name)
        .and_then(|e| e.1)
        .map(|e| vec![e.to_owned()]);
    if list_ok && entry != want_entry {
        add(
            "wrong-entrypoint",
            format!("entrypoint is {entry:?}, expected {want_entry:?}"),
        );
    }

    // Secrets are references, never values.
    if !svc["environment"].is_badvalue() && svc["environment"].as_hash().is_none() {
        add(
            "environment-not-mapping",
            "environment must be a mapping".into(),
        );
    }
    if let Some(env) = svc["environment"].as_hash() {
        for (k, v) in env {
            let (Some(k), v) = (k.as_str(), yaml_text(v)) else {
                continue;
            };
            if has_secret_word(k) && !is_lab_reference(&v) {
                add(
                    "literal-secret",
                    format!("environment {k} is not a ${{GD_LAB_...:?...}} reference"),
                );
            }
        }
    }
    let command = strings(&svc["command"]).unwrap_or_default();
    let health = strings(&svc["healthcheck"]["test"]).unwrap_or_default();
    for (where_, items) in [("command", &command), ("healthcheck", &health)] {
        for (flag, value) in options(items) {
            if has_secret_word(&flag) && !value.as_deref().is_some_and(is_lab_reference) {
                add(
                    "literal-secret",
                    format!("{where_} option {flag} is not a ${{GD_LAB_...:?...}} reference"),
                );
            }
        }
    }

    // Regtest, per node. Option spellings are normalised, and any other chain
    // selector, or a second one, is refused.
    match name {
        "bitcoind" => {
            let ok = single_regtest_selector(
                &command,
                &[
                    "chain", "regtest", "testnet", "testnet4", "signet", "main", "mainnet",
                ],
                |n, v| n == "chain" && v == "regtest",
            ) && health.iter().any(|h| h == "-chain=regtest");
            if !ok {
                add(
                    "not-regtest",
                    "bitcoind must run exactly one chain selector, -chain=regtest".into(),
                );
            }
            let allow: Vec<&String> = command
                .iter()
                .filter(|c| c.starts_with("-rpcallowip="))
                .collect();
            let want = format!("-rpcallowip={SUBNET}");
            if allow.is_empty() || allow.iter().any(|a| **a != want) {
                add(
                    "rpc-open-beyond-lab",
                    format!("every -rpcallowip must be exactly {SUBNET}"),
                );
            }
        }
        "lnd" => {
            let ok = single_regtest_selector(
                &command,
                &[
                    "bitcoin.regtest",
                    "bitcoin.mainnet",
                    "bitcoin.testnet",
                    "bitcoin.testnet4",
                    "bitcoin.signet",
                    "bitcoin.simnet",
                ],
                |n, v| n == "bitcoin.regtest" && (v.is_empty() || v == "true"),
            ) && health.iter().any(|h| h == "--network=regtest");
            if !ok {
                add(
                    "not-regtest",
                    "lnd must run exactly one chain selector, --bitcoin.regtest".into(),
                );
            }
        }
        "cln" => {
            let selectors: Vec<_> = options(&command)
                .into_iter()
                .filter(|(n, _)| {
                    ["network", "mainnet", "testnet", "signet", "regtest"].contains(&n.as_str())
                })
                .collect();
            let selectors_ok = selectors.len() <= 1
                && selectors.iter().all(|(n, v)| {
                    (n == "network" && v.as_deref() == Some("regtest")) || n == "regtest"
                });
            let ok = svc["environment"]["LIGHTNINGD_NETWORK"].as_str() == Some("regtest")
                && selectors_ok
                && health.iter().any(|h| h == "--network=regtest");
            if !ok {
                add("not-regtest", "cln must run on regtest, once".into());
            }
        }
        "nutshell" => {
            let env = keys(&svc["environment"]);
            let others = env.iter().any(|k| {
                k != "MINT_BACKEND_BOLT11_SAT"
                    && (k.starts_with("MINT_BACKEND_") || k.starts_with("MINT_LIGHTNING_BACKEND"))
            });
            if svc["environment"]["MINT_BACKEND_BOLT11_SAT"].as_str() != Some("FakeWallet")
                || others
            {
                add("mint-not-fake", "the mint must use only FakeWallet".into());
            }
        }
        _ => {}
    }
}

/// An environment value as text (compose accepts numbers and booleans too).
fn yaml_text(y: &Yaml) -> String {
    match y {
        Yaml::String(s) | Yaml::Real(s) => s.clone(),
        Yaml::Integer(i) => i.to_string(),
        Yaml::Boolean(b) => b.to_string(),
        _ => String::new(),
    }
}

fn describe(problems: &[Problem]) -> String {
    problems
        .iter()
        .map(|p| format!("{}: {}", p.code, p.detail))
        .collect::<Vec<_>>()
        .join("\n")
}

/// Unsafe edits to the real file: (text to find, text to put there, the
/// problem code that must catch it). An empty `from` appends `to` to the end.
const MUTATIONS: [(&str, &str, &str); 37] = [
    (
        "bitcoin/bitcoin@sha256:d2454aaf2ff4ce1ebbc49f4aa05ed044c907b849a80a3f4c0ad23e488e50bbe0",
        "bitcoin/bitcoin:32.1",
        "unpinned-image",
    ),
    (
        "    user: \"101:101\"\n",
        "    user: \"101:101\"\n    ports: [\"18443:18443\"]\n",
        "host-port",
    ),
    (
        "    user: \"101:101\"\n",
        "    user: \"101:101\"\n    privileged: true\n",
        "privileged",
    ),
    (
        "    user: \"101:101\"\n",
        "    user: \"101:101\"\n    cap_add: [NET_ADMIN]\n",
        "capability-added",
    ),
    (
        "    user: \"101:101\"\n",
        "    user: \"101:101\"\n    volumes: [\"/var/run/docker.sock:/var/run/docker.sock\"]\n",
        "host-mount",
    ),
    (
        "    user: \"101:101\"\n",
        "    user: \"101:101\"\n    network_mode: host\n",
        "host-namespace",
    ),
    (
        "    internal: true",
        "    internal: false",
        "network-not-internal",
    ),
    (
        "      - -chain=regtest\n",
        "      - -chain=main\n",
        "not-regtest",
    ),
    (
        "      - --bitcoin.regtest\n",
        "      - --bitcoin.mainnet\n",
        "not-regtest",
    ),
    (
        "      LIGHTNINGD_NETWORK: regtest",
        "      LIGHTNINGD_NETWORK: bitcoin",
        "not-regtest",
    ),
    ("    mem_limit: 512m\n", "", "no-memory-limit"),
    (
        "    mem_limit: 384m\n    memswap_limit: 384m",
        "    mem_limit: 4g\n    memswap_limit: 4g",
        "memory-over-budget",
    ),
    (
        "${GD_LAB_MINT_KEY:?run lab/up.sh, not docker compose}",
        "gdlabcanary-0011223344556677",
        "literal-secret",
    ),
    ("    user: \"101:101\"", "    user: \"0:0\"", "root-user"),
    (
        "    read_only: true",
        "    read_only: false",
        "writable-root",
    ),
    ("    cap_drop: [ALL]\n", "", "capabilities-not-dropped"),
    (
        "    security_opt: [\"no-new-privileges:true\"]\n",
        "",
        "privileges-not-locked",
    ),
    ("  nutshell:\n", "  nutshell2:\n", "unexpected-services"),
    (
        "MINT_BACKEND_BOLT11_SAT: FakeWallet",
        "MINT_BACKEND_BOLT11_SAT: LndRestWallet",
        "mint-not-fake",
    ),
    (
        "-rpcallowip=172.29.208.0/24",
        "-rpcallowip=0.0.0.0/0",
        "rpc-open-beyond-lab",
    ),
    ("", "volumes:\n  chain: {}\n", "named-volume"),
    (
        "    command: [\"python3\", \"-m\", \"cashu.mint\"]",
        "    command: python3 -m cashu.mint",
        "command-not-list",
    ),
    (
        "      - -fallbackfee=0.0002\n",
        "      - -fallbackfee=0.0002\n      - --chain=main\n",
        "not-regtest",
    ),
    (
        "      - -chain=regtest\n",
        "      - -regtest\n",
        "not-regtest",
    ),
    (
        "      - --alias=gd-lab-cln\n",
        "      - --alias=gd-lab-cln\n      - --network\n      - bitcoin\n",
        "not-regtest",
    ),
    (
        "      - --bitcoin.regtest\n",
        "      - --bitcoin.regtest\n      - --bitcoin.mainnet\n",
        "not-regtest",
    ),
    (
        "    entrypoint: [\"bitcoind\"]",
        "    entrypoint: [\"sh\", \"-c\", \"exec bitcoind -chain=main\"]",
        "wrong-entrypoint",
    ),
    (
        "    user: \"1000:1000\"\n",
        "    user: \"1000:1000\"\n    entrypoint: [\"sh\"]\n",
        "wrong-entrypoint",
    ),
    (
        "    mem_limit: 512m\n    memswap_limit: 512m\n",
        "    mem_limit: 0m\n    memswap_limit: 0m\n",
        "no-memory-limit",
    ),
    ("      - /root/.lnd:size=1m\n", "", "tmpfs-missing"),
    (
        "    security_opt: [\"no-new-privileges:true\"]\n",
        "    security_opt: [\"no-new-privileges:true\", \"seccomp=unconfined\"]\n",
        "privileges-not-locked",
    ),
    (
        "    internal: true",
        "    internal: true\n    attachable: true",
        "network-keys",
    ),
    (
        "gateway_mode_ipv4: isolated",
        "gateway_mode_ipv4: nat",
        "network-not-isolated",
    ),
    (
        "        - subnet: 172.29.208.0/24",
        "        - subnet: 172.29.208.0/24\n          gateway: 172.29.208.1",
        "network-keys",
    ),
    (
        "    environment:\n      HOME: /data\n    depends_on:",
        "    environment: [\"HOME=/data\"]\n    depends_on:",
        "environment-not-mapping",
    ),
    (
        "      - --bitcoind.rpcpass=${GD_LAB_RPC_PASSWORD:?run lab/up.sh, not docker compose}\n",
        "      - --bitcoind.rpcpass\n      - hunter2\n",
        "literal-secret",
    ),
    (
        "\"--network=regtest\", \"getinfo\"]",
        "\"--network=regtest\", \"--rpcpassword=hunter2\", \"getinfo\"]",
        "literal-secret",
    ),
];

/// The real compose file passes every check.
#[test]
fn lab_compose_passes_every_check() {
    let problems = check(&read("lab/compose.yml"));
    assert!(problems.is_empty(), "problems:\n{}", describe(&problems));
}

/// Each named unsafe edit is refused with its own problem code, so the
/// checker itself is tested and can never silently stop checking.
#[test]
fn every_unsafe_change_is_caught() {
    let original = read("lab/compose.yml");
    let mut misses = Vec::new();
    for (n, (from, to, code)) in MUTATIONS.iter().enumerate() {
        let n = n + 1;
        let mutated = if from.is_empty() {
            format!("{original}{to}")
        } else {
            assert!(
                original.contains(from),
                "mutation {n}: the original has no {from:?}, so it would do nothing"
            );
            original.replacen(from, to, 1)
        };
        let problems = check(&mutated);
        if problems.iter().any(|p| p.code == "unparseable") {
            misses.push(format!("mutation {n} ({code}): the edit no longer parses"));
        } else if !problems.iter().any(|p| p.code == *code) {
            misses.push(format!(
                "mutation {n}: expected {code}, got [{}]",
                problems
                    .iter()
                    .map(|p| p.code)
                    .collect::<Vec<_>>()
                    .join(", ")
            ));
        }
    }
    assert!(misses.is_empty(), "missed:\n{}", misses.join("\n"));
}

/// The README names every pinned image and version, so the docs and the
/// compose file cannot drift apart.
#[test]
fn lab_readme_lists_every_pinned_image() {
    let readme = read("lab/README.md");
    let mut missing = Vec::new();
    for (_, _, image, version, _) in EXPECTED {
        for needle in [image, version] {
            if !readme.contains(needle) {
                missing.push(needle);
            }
        }
    }
    for needle in ["GPL-3.0", "lab/up.sh", "lab/down.sh"] {
        if !readme.contains(needle) {
            missing.push(needle);
        }
    }
    assert!(missing.is_empty(), "lab/README.md lacks: {missing:?}");
}

/// The scripts only touch the `gd-lab` project, check every chain, and never
/// reach for anything dangerous.
#[test]
fn lab_scripts_stay_on_the_lab_project_and_regtest() {
    let up = read("lab/up.sh");
    let down = read("lab/down.sh");
    let mut problems = Vec::new();
    for (name, text) in [("up.sh", &up), ("down.sh", &down)] {
        for needle in [
            "#!/usr/bin/env bash\n",
            "set -euo pipefail",
            "PROJECT=gd-lab",
        ] {
            if (needle.starts_with('#') && !text.starts_with(needle))
                || (!needle.starts_with('#') && !text.contains(needle))
            {
                problems.push(format!("{name} lacks {needle:?}"));
            }
        }
        for banned in [
            "-chain=main",
            "mainnet",
            "-testnet",
            "-signet",
            "prune",
            "--privileged",
            "docker.sock",
            "sudo",
            "eval ",
            "rm -rf /",
            "docker run",
        ] {
            if text.contains(banned) {
                problems.push(format!("{name} contains {banned:?}"));
            }
        }
    }
    for needle in [
        "-chain=regtest",
        "--network=regtest",
        "jq -r .chain)\" = regtest",
        "jq -r '.chains[0].network')\" = regtest",
        "jq -r .network)\" = regtest",
        "exit 3",
        "unset GD_LAB_RPC_PASSWORD",
        "-stdinrpcpass",
        "trap cleanup EXIT",
        "mkdir \"$LOCK\"",
    ] {
        if !up.contains(needle) {
            problems.push(format!("up.sh lacks {needle:?}"));
        }
    }
    for needle in [
        "down --volumes --remove-orphans",
        "rm -rf \"$LAB_DIR/.data\"",
    ] {
        if !down.contains(needle) {
            problems.push(format!("down.sh lacks {needle:?}"));
        }
    }
    #[cfg(unix)]
    {
        use std::os::unix::fs::PermissionsExt;
        for rel in ["lab/up.sh", "lab/down.sh"] {
            let mode = fs::metadata(root().join(rel)).unwrap().permissions().mode();
            if mode & 0o100 == 0 {
                problems.push(format!("{rel} is not executable by its owner"));
            }
        }
    }
    assert!(problems.is_empty(), "problems:\n{}", problems.join("\n"));
}

fn walk(dir: &Path, found: &mut Vec<PathBuf>) {
    let mut entries: Vec<_> = fs::read_dir(dir)
        .unwrap_or_else(|e| panic!("reading {}: {e}", dir.display()))
        .map(|e| e.unwrap().path())
        .collect();
    entries.sort();
    for path in entries {
        if path.is_dir() {
            if path.file_name().is_some_and(|n| n == ".data") {
                continue;
            }
            walk(&path, found);
        } else {
            found.push(path);
        }
    }
}

/// The sorted list of tracked regular files under `lab/`, from `git ls-files`
/// (the working-tree walk is only a fallback outside a git checkout).
fn tracked_lab_files() -> Vec<PathBuf> {
    let out = std::process::Command::new("git")
        .args(["ls-files", "-z", "--", "lab"])
        .current_dir(root())
        .output();
    let mut files: Vec<PathBuf> = match out {
        Ok(o) if o.status.success() => String::from_utf8_lossy(&o.stdout)
            .split('\0')
            .filter(|p| !p.is_empty())
            .map(|p| root().join(p))
            .collect(),
        _ => {
            assert!(
                !root().join(".git").exists(),
                "git ls-files failed inside a git checkout"
            );
            let mut found = Vec::new();
            walk(&root().join("lab"), &mut found);
            found
        }
    };
    files.sort();
    files.retain(|p| p.symlink_metadata().is_ok_and(|m| m.file_type().is_file()));
    files
}

/// No tracked file under `lab/` holds a generated credential, nothing under
/// `lab/.data/` is tracked, and `lab/.data/` is gitignored.
#[test]
fn no_generated_secret_is_committed() {
    let files = tracked_lab_files();
    assert!(!files.is_empty(), "found no files under lab/");
    for path in files {
        let rel = path.strip_prefix(root()).unwrap_or(&path);
        assert!(
            !rel.starts_with("lab/.data"),
            "{} is tracked, but lab/.data must never be committed",
            rel.display()
        );
        let text = String::from_utf8_lossy(
            &fs::read(&path).unwrap_or_else(|e| panic!("reading {}: {e}", path.display())),
        )
        .into_owned();
        assert!(
            !has_canary(&text),
            "{} contains a {CANARY}... credential",
            path.display()
        );
    }
    let ignore = read(".gitignore");
    assert!(
        ignore.lines().any(|l| l == "lab/.data/"),
        ".gitignore must list lab/.data/"
    );
}
