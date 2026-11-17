//! The regtest lab's compose file and scripts (Phase 0.8), checked without
//! starting Docker.
//!
//! Deterministic by design: no Docker, no network, no clock, nothing random.
//! `check()` reads `lab/compose.yml` the way Docker does (the file uses no YAML
//! anchors) and returns every problem it finds, in a stable order. The checker
//! is itself tested: `every_unsafe_change_is_caught` makes 60 named unsafe
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
/// The two tool services: (compose name, exact image, user, compose profile).
/// Neither is started by `lab/up.sh` without its profile. `probe` is a pinned
/// curl image; `scanner` is built locally from `lab/scanner/Dockerfile` and
/// carries a fixed local tag, so it is built once, not per run.
const TOOLS: [(&str, &str, &str, &str); 2] = [
    (
        "probe",
        "curlimages/curl@sha256:3fb7e13e5d179a845c97d78204f3f1064d1907037f26a3ebf91710571151fd93",
        "100:101",
        "probe",
    ),
    ("scanner", "gd-lab-scanner:local", "65532:65532", "scan"),
];
/// The one tmpfs entry the scanner may have: its state folder.
const SCANNER_STATE_TMPFS: &str = "/state:uid=65532,gid=65532,mode=0700,size=1m";
/// The only keys a lab service may use.
const ALLOWED_SERVICE_KEYS: [&str; 21] = [
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
    "profiles",
];
/// Keys that have their own problem code, so they never also count as `unknown-key`.
const SPECIFIC_KEYS: [&str; 14] = [
    "build",
    "platform",
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
const ENTRYPOINTS: [(&str, Option<&str>); 7] = [
    ("probe", Some("curl")),
    ("scanner", None),
    ("bitcoind", Some("bitcoind")),
    ("cln", None),
    ("lnd", None),
    ("nutshell", None),
    ("strfry", None),
];
/// Every tmpfs mount each service must have, and no others.
const TMPFS_TARGETS: [(&str, &[&str]); 7] = [
    ("probe", &[]),
    ("scanner", &["/state"]),
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

/// A tmpfs `size=` value (`256m`, `1g`, `512k` or plain bytes) in whole MiB, rounded up.
fn size_mib(s: &str) -> Option<u64> {
    let last = s.chars().last()?;
    let (digits, unit) = if last.is_ascii_digit() {
        (s, 1)
    } else {
        let unit = match last {
            'k' => 1024,
            'm' => 1024 * 1024,
            'g' => 1024 * 1024 * 1024,
            _ => return None,
        };
        (&s[..s.len() - 1], unit)
    };
    if digits.is_empty() || !digits.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    let bytes = digits.parse::<u64>().ok()?.checked_mul(unit)?;
    Some(bytes.div_ceil(1024 * 1024))
}

/// A value for a secret-looking name must be a `${GD_LAB_...:?...}` reference.
/// The generated values `lab/up.sh` puts in `lab/.data/lab.env` that the
/// compose file may refer to.
const ALLOWED_REFERENCES: [&str; 4] = [
    "GD_LAB_RPC_PASSWORD",
    "GD_LAB_RPCAUTH",
    "GD_LAB_WATCH_RPCAUTH",
    "GD_LAB_MINT_KEY",
];

/// Whether every `$` in `s` starts a reference of exactly the form
/// `${NAME:?message}`, with an allowed NAME. That refuses `$VAR`, `$$`,
/// `${NAME}` and `${NAME:-default}`, which could resolve to a literal value.
fn interpolations_ok(s: &str) -> bool {
    let mut rest = s;
    while let Some(i) = rest.find('$') {
        let Some(body) = rest[i..].strip_prefix("${") else {
            return false;
        };
        let Some(end) = body.find('}') else {
            return false;
        };
        let Some((name, message)) = body[..end].split_once(":?") else {
            return false;
        };
        if !ALLOWED_REFERENCES.contains(&name) || message.is_empty() || message.contains('$') {
            return false;
        }
        rest = &body[end + 1..];
    }
    true
}

/// A value that is exactly one `${NAME:?message}` reference and nothing else.
fn is_lab_reference(v: &str) -> bool {
    v.starts_with("${") && v.ends_with('}') && v.matches('$').count() == 1 && interpolations_ok(v)
}

/// Every string in a YAML value, keys included.
fn all_strings<'a>(y: &'a Yaml, out: &mut Vec<&'a str>) {
    match y {
        Yaml::String(s) => out.push(s),
        Yaml::Array(a) => a.iter().for_each(|v| all_strings(v, out)),
        Yaml::Hash(h) => h.iter().for_each(|(k, v)| {
            all_strings(k, out);
            all_strings(v, out);
        }),
        _ => {}
    }
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
    // A bare CR is a line break to YAML but not to `lines()`, so it could hide a
    // tag or a key from the checks below. Only newline and tab may be control characters.
    if let Some(c) = text
        .chars()
        .find(|c| c.is_control() && *c != '\n' && *c != '\t')
    {
        out.push(problem(
            "control-char",
            format!("control character {c:?} is not allowed in the compose file"),
        ));
        return out;
    }
    // A YAML tag (`!reset`, `!override`, any `!`) can make Compose read something
    // other than what this checker reads, so none is allowed on any line that is
    // not a whole-line comment.
    if let Some(line) = text
        .lines()
        .find(|l| !l.trim_start().starts_with('#') && l.contains('!'))
    {
        out.push(problem(
            "yaml-tag",
            format!("a YAML tag (!) is not allowed: {line:?}"),
        ));
        return out;
    }
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
    let want: BTreeSet<String> = EXPECTED
        .iter()
        .map(|e| e.0.to_owned())
        .chain(TOOLS.iter().map(|t| t.0.to_owned()))
        .collect();
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
    // The tool services, counted in the budget as if they ran with the rest.
    for (name, image, user, _) in TOOLS {
        let svc = &services[name];
        if svc.as_hash().is_none() {
            continue;
        }
        check_service(&mut out, name, "", image, "", user, svc);
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

    // Every `$` in the file is an allowed `${NAME:?message}` reference.
    let mut strs = Vec::new();
    all_strings(doc, &mut strs);
    if let Some(bad) = strs.iter().find(|s| !interpolations_ok(s)) {
        out.push(problem(
            "bad-interpolation",
            format!(
                "{bad:?} has a `$` that is not exactly ${{NAME:?message}} with an allowed name"
            ),
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
    let tool = TOOLS.iter().find(|t| t.0 == name);
    let found = svc["image"].as_str().unwrap_or("");
    if name == "scanner" {
        // Built locally: the fixed tag, never a registry name.
        if found != image {
            add(
                "wrong-image",
                format!("image {found:?} is not the fixed local tag {image:?}"),
            );
        }
    } else if !is_pinned(found) {
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
    if tool.is_some() {
        // A tool has only the service label, so it is never taken for a lab service.
        if keys(labels) != ["org.guard-dog.lab.service"]
            || labels["org.guard-dog.lab.service"].as_str() != Some(name)
        {
            add(
                "wrong-labels",
                "a tool has exactly the label org.guard-dog.lab.service".into(),
            );
        }
    }
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
    if tool.is_none()
        && (label_keys != want_keys
            || labels["org.guard-dog.lab.service"].as_str() != Some(name)
            || labels["org.guard-dog.lab.id"].as_str() != Some(id)
            || labels["org.guard-dog.lab.expected-version"].as_str() != Some(version)
            || !software_ok)
    {
        add(
            "wrong-labels",
            format!("labels must be the four org.guard-dog.lab.* keys for {id} {version}"),
        );
    }

    // Profiles: a tool is started only by its own profile; a lab service has none.
    let profiles = strings(&svc["profiles"]);
    match tool {
        Some(t) => {
            if profiles.as_deref() != Some(&[t.3.to_owned()]) {
                add("profile", format!("profiles must be exactly [{}]", t.3));
            }
        }
        None => {
            if !svc["profiles"].is_badvalue() {
                add("profile", "a lab service must have no profiles".into());
            }
        }
    }
    // A build is allowed only for the scanner, from the one reviewed Dockerfile.
    let build = &svc["build"];
    if name == "scanner" {
        if keys(build).len() != 2
            || build["context"].as_str() != Some("..")
            || build["dockerfile"].as_str() != Some("lab/scanner/Dockerfile")
        {
            add(
                "build",
                "build must be exactly {context: .., dockerfile: lab/scanner/Dockerfile}".into(),
            );
        }
    } else if !build.is_badvalue() {
        add("build", "only the scanner may be built".into());
    }
    // Credentials never go in a tool's environment: they arrive on stdin.
    if tool.is_some() && !svc["environment"].is_badvalue() {
        add(
            "tool-environment",
            "a tool has no environment: credentials arrive on stdin".into(),
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
    if has("platform") {
        add(
            "foreign-platform",
            "platform is set: the lab must run the host's own architecture".into(),
        );
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
    let mem_cap = svc["mem_limit"].as_str().and_then(mem_mib).unwrap_or(0);
    let tmpfs_list = if svc["tmpfs"].is_badvalue() && name == "probe" {
        Some(Vec::new())
    } else {
        strings(&svc["tmpfs"])
    };
    let tmpfs_ok = tmpfs_list.is_some_and(|v| {
        v.iter().all(|t| {
            t.starts_with('/')
                && t.split_once(':').is_some_and(|(_, opts)| {
                    let opts: Vec<&str> = opts.split(',').collect();
                    let sizes: Vec<&str> = opts
                        .iter()
                        .filter_map(|o| o.strip_prefix("size="))
                        .collect();
                    // Only these options, and exactly one size (Docker keeps the last
                    // of several, and nr_blocks / nr_inodes can lift the bound).
                    let allowed = opts.iter().all(|o| {
                        ["uid=", "gid=", "mode=", "size="]
                            .iter()
                            .any(|p| o.starts_with(p))
                    });
                    allowed
                        && sizes.len() == 1
                        && size_mib(sizes[0]).is_some_and(|m| m >= 1 && m <= mem_cap)
                })
        })
    });
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
    if name == "scanner"
        && strings(&svc["tmpfs"]).as_deref() != Some(&[SCANNER_STATE_TMPFS.to_owned()])
    {
        add(
            "tmpfs-unbounded",
            format!("the scanner's tmpfs must be exactly {SCANNER_STATE_TMPFS}"),
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

    // A bare `-` or `--` ends option parsing, so options after it would be ignored.
    let entry_items = strings(&svc["entrypoint"]).unwrap_or_default();
    for (where_, items) in [
        ("command", &command),
        ("healthcheck", &health),
        ("entrypoint", &entry_items),
    ] {
        if items.iter().any(|i| i == "-" || i == "--") {
            add(
                "command-terminator",
                format!("{where_} has a bare - or -- item"),
            );
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
            // Core stops reading options at the first item that is not one.
            if command.iter().any(|c| !c.starts_with('-')) {
                add(
                    "command-terminator",
                    "every bitcoind item must be an option".into(),
                );
            }
            // RPC access: normalised, so `--rpcallowip v` and `-rpcallowip=v` read alike.
            let opts = options(&command);
            let values = |name: &str| -> Vec<Option<String>> {
                opts.iter()
                    .filter(|(n, _)| n == name)
                    .map(|(_, v)| v.clone())
                    .collect()
            };
            let allow = values("rpcallowip");
            let bind = values("rpcbind");
            if allow.is_empty()
                || allow.iter().any(|a| a.as_deref() != Some(SUBNET))
                || bind != [Some("0.0.0.0".to_owned())]
            {
                add(
                    "rpc-open-beyond-lab",
                    format!("rpcallowip must be only {SUBNET} and rpcbind only 0.0.0.0"),
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
const MUTATIONS: [(&str, &str, &str); 60] = [
    (
        "    user: \"101:101\"\n",
        "    user: \"101:101\"\n    platform: linux/386\n",
        "foreign-platform",
    ),
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
    (
        "      - -chain=regtest\n",
        "      - \"-\"\n      - -chain=regtest\n",
        "command-terminator",
    ),
    (
        "      - --alias=gd-lab-cln\n",
        "      - --\n      - --alias=gd-lab-cln\n",
        "command-terminator",
    ),
    (
        "      - -chain=regtest\n",
        "      - some-word\n      - -chain=regtest\n",
        "command-terminator",
    ),
    (
        "-rpcallowip=172.29.208.0/24",
        "-rpcallowip=172.29.208.0/24\n      - --rpcallowip=0.0.0.0/0",
        "rpc-open-beyond-lab",
    ),
    (
        "-rpcallowip=172.29.208.0/24",
        "-rpcallowip=172.29.208.0/24\n      - --rpcallowip\n      - 0.0.0.0/0",
        "rpc-open-beyond-lab",
    ),
    (
        "      - -rpcbind=0.0.0.0\n",
        "      - -rpcbind=0.0.0.0\n      - --rpcbind=::\n",
        "rpc-open-beyond-lab",
    ),
    (
        "${GD_LAB_MINT_KEY:?run lab/up.sh, not docker compose}",
        "${GD_LAB_MISSING:-hunter2:?x}",
        "bad-interpolation",
    ),
    (
        "      PYTHONPATH: /app",
        "      PYTHONPATH: /app:$HOME",
        "bad-interpolation",
    ),
    (
        "${GD_LAB_RPCAUTH:?run lab/up.sh, not docker compose}",
        "${GD_LAB_OTHER:?run lab/up.sh, not docker compose}",
        "bad-interpolation",
    ),
    (
        "      - /root/.lnd:size=1m\n",
        "      - /root/.lnd:size=0\n",
        "tmpfs-unbounded",
    ),
    (
        "      - /data:uid=1000,gid=1000,mode=0700,size=256m\n",
        "      - /data:uid=1000,gid=1000,mode=0700,size=4096m\n",
        "tmpfs-unbounded",
    ),
    (
        "    networks: [lab]\n",
        "    networks: !reset [lab]\n",
        "yaml-tag",
    ),
    (
        "    cap_drop: [ALL]\n",
        "    cap_drop: !override [ALL]\n",
        "yaml-tag",
    ),
    (
        "    read_only: true",
        "    read_only: !!bool true",
        "yaml-tag",
    ),
    (
        "      - /root/.lnd:size=1m\n",
        "      - /root/.lnd:size=1m,size=0\n",
        "tmpfs-unbounded",
    ),
    (
        "      - /tmp:size=16m\n",
        "      - /tmp:size=16m,nr_inodes=0\n",
        "tmpfs-unbounded",
    ),
    (
        "    cap_drop: [ALL]\n",
        "# comment\r    cap_drop: !reset [ALL]\n",
        "control-char",
    ),
    // A published REST port: LND's REST must stay on the internal network.
    (
        "    image: lightninglabs/lnd@sha256:54b3c87ad0bc3fea3fab8af23ace6421147ea97e6b56bf3911592d7853c185b8\n",
        "    image: lightninglabs/lnd@sha256:54b3c87ad0bc3fea3fab8af23ace6421147ea97e6b56bf3911592d7853c185b8\n    ports: [\"8080:8080\"]\n",
        "host-port",
    ),
    // The probe without cap_drop.
    (
        "    entrypoint: [\"curl\"]\n    networks: [lab]\n    read_only: true\n    cap_drop: [ALL]\n",
        "    entrypoint: [\"curl\"]\n    networks: [lab]\n    read_only: true\n",
        "capabilities-not-dropped",
    ),
    // The scanner with a volume.
    (
        "    profiles: [scan]\n",
        "    profiles: [scan]\n    volumes: [\"./data:/state\"]\n",
        "host-mount",
    ),
    // The scanner on a network that is not the internal lab one.
    (
        "    tmpfs:\n      - /state:uid=65532,gid=65532,mode=0700,size=1m\n    networks: [lab]\n",
        "    tmpfs:\n      - /state:uid=65532,gid=65532,mode=0700,size=1m\n    networks: [bridge]\n",
        "wrong-network",
    ),
    // An unpinned probe image.
    (
        "curlimages/curl@sha256:3fb7e13e5d179a845c97d78204f3f1064d1907037f26a3ebf91710571151fd93",
        "curlimages/curl:8.23.0",
        "unpinned-image",
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
    for (_, image, _, _) in TOOLS {
        if image.contains("@sha256:") && !readme.contains(image) {
            missing.push(image);
        }
    }
    for needle in [
        "GPL-3.0",
        "lab/up.sh",
        "lab/down.sh",
        "gd-lab-scanner:local",
    ] {
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
        "lab_lock",
        "lab_teardown",
    ] {
        if !up.contains(needle) {
            problems.push(format!("up.sh lacks {needle:?}"));
        }
    }
    for needle in ["lab_lock", "lab_teardown", "trap lab_unlock EXIT"] {
        if !down.contains(needle) {
            problems.push(format!("down.sh lacks {needle:?}"));
        }
    }
    if down.contains("GD_LAB_LOCK_HELD") || up.contains("GD_LAB_LOCK_HELD") {
        problems.push("a lock bypass variable is back".to_owned());
    }
    // The shared library holds the teardown, and gets the same banned-word check.
    let lib = read("lab/lib.sh");
    for needle in [
        "down --volumes --remove-orphans",
        "rm -rf \"$LAB_DIR/.data\"",
        "mkdir \"$LOCK\"",
    ] {
        if !lib.contains(needle) {
            problems.push(format!("lib.sh lacks {needle:?}"));
        }
    }
    for banned in [
        "mainnet",
        "prune",
        "docker.sock",
        "sudo",
        "eval ",
        "rm -rf /",
        "docker run",
        "--privileged",
    ] {
        if lib.contains(banned) {
            problems.push(format!("lib.sh contains {banned:?}"));
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

/// A scratch copy of the lab scripts with fake `docker`, `jq` and `openssl`
/// commands first on the PATH, so the scripts can run without Docker.
#[cfg(unix)]
struct Scratch {
    dir: PathBuf,
}

#[cfg(unix)]
impl Scratch {
    fn new(name: &str, openssl: &str) -> Self {
        use std::os::unix::fs::PermissionsExt;
        let dir = std::env::temp_dir().join(format!("gd-lab-test-{}-{name}", std::process::id()));
        let _ = fs::remove_dir_all(&dir);
        fs::create_dir_all(dir.join("lab")).unwrap();
        fs::create_dir_all(dir.join("bin")).unwrap();
        for f in ["up.sh", "down.sh", "lib.sh"] {
            fs::copy(root().join("lab").join(f), dir.join("lab").join(f)).unwrap();
        }
        for (cmd, body) in [("docker", "exit 0"), ("jq", "exit 0"), ("openssl", openssl)] {
            let p = dir.join("bin").join(cmd);
            fs::write(&p, format!("#!/bin/sh\n{body}\n")).unwrap();
            fs::set_permissions(&p, fs::Permissions::from_mode(0o755)).unwrap();
        }
        Scratch { dir }
    }

    /// Run `lab/<script>` with only the fake commands and the system tools.
    fn run(&self, script: &str) -> std::process::Output {
        self.run_with(script, &[])
    }

    fn run_with(&self, script: &str, args: &[&str]) -> std::process::Output {
        std::process::Command::new("/bin/bash")
            .arg(self.dir.join("lab").join(script))
            .args(args)
            .env_clear()
            .env(
                "PATH",
                format!("{}:/usr/bin:/bin", self.dir.join("bin").display()),
            )
            .output()
            .unwrap()
    }

    fn lock(&self) -> PathBuf {
        self.dir.join("lab/.lock")
    }
}

#[cfg(unix)]
impl Drop for Scratch {
    fn drop(&mut self) {
        let _ = fs::remove_dir_all(&self.dir);
    }
}

/// A failing or odd `openssl` must stop `up.sh` before anything starts: no
/// prefix-only password and no empty salt may ever reach lab.env.
#[cfg(unix)]
#[test]
fn a_failing_openssl_stops_up_sh_before_anything_starts() {
    for (name, body) in [
        ("exit1", "exit 1"),
        ("silent", "exit 0"),
        ("short", "printf zz"),
    ] {
        let s = Scratch::new(name, body);
        let out = s.run("up.sh");
        let err = String::from_utf8_lossy(&out.stderr);
        assert_eq!(out.status.code(), Some(1), "{name}: {err}");
        assert!(err.contains("openssl"), "{name}: {err}");
        assert!(
            !err.contains("REFUSED"),
            "{name} got past credential generation: {err}"
        );
        assert!(
            !s.dir.join("lab/.data").exists(),
            "{name}: lab/.data left behind"
        );
        assert!(
            s.lock().symlink_metadata().is_err(),
            "{name}: lock left behind"
        );
    }
}

/// An existing lock is never taken over: live and dead owners are both refused
/// with a hint, `--unlock` removes only the lock directory, and anything else
/// at that path is left alone.
#[cfg(unix)]
#[test]
fn an_existing_lock_is_refused_until_unlock() {
    use std::os::unix::fs::symlink;
    let s = Scratch::new("lock", "exit 1");
    let lock = s.lock();
    let refused = |s: &Scratch, want: &str| {
        let out = s.run("down.sh");
        let err = String::from_utf8_lossy(&out.stderr).into_owned();
        assert_eq!(out.status.code(), Some(1), "{err}");
        assert!(err.contains(want) && err.contains("--unlock"), "{err}");
        let out = s.run("up.sh");
        assert_eq!(out.status.code(), Some(1));
    };

    // A dead owner, and a live one: both refused, lock untouched.
    fs::create_dir(&lock).unwrap();
    fs::write(lock.join("pid"), "99999999\n").unwrap();
    refused(&s, "(not running)");
    assert!(lock.join("pid").exists());
    fs::write(lock.join("pid"), format!("{}\n", std::process::id())).unwrap();
    refused(&s, "(running)");
    assert!(lock.join("pid").exists());

    // --unlock removes just the lock directory.
    let out = s.run_with("down.sh", &["--unlock"]);
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(lock.symlink_metadata().is_err(), "lock not removed");

    // With no lock, down.sh works and leaves none behind.
    let out = s.run("down.sh");
    assert!(
        out.status.success(),
        "{}",
        String::from_utf8_lossy(&out.stderr)
    );
    assert!(lock.symlink_metadata().is_err());

    // A symlink or a file at the lock path is refused, and --unlock leaves it.
    fs::write(s.dir.join("precious"), "keep").unwrap();
    symlink(s.dir.join("precious"), &lock).unwrap();
    refused(&s, "names no process");
    let out = s.run_with("down.sh", &["--unlock"]);
    assert_eq!(out.status.code(), Some(1));
    assert_eq!(fs::read_to_string(s.dir.join("precious")).unwrap(), "keep");
    assert!(lock.symlink_metadata().is_ok(), "the symlink must stay");
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

/// Whether an index path must never be committed: anything under `lab/.data`
/// (where `up.sh` writes credentials) or the lock. Case-insensitive, for macOS.
fn forbidden_index_path(path: &str) -> bool {
    let p = path.to_lowercase();
    p.starts_with("lab/.data") || p.starts_with("lab/.lock")
}

/// Parse `git ls-files -s -z` output into (mode, path) pairs.
fn parse_index(raw: &str) -> Vec<(String, String)> {
    raw.split('\0')
        .filter(|e| !e.is_empty())
        .filter_map(|e| {
            let (meta, path) = e.split_once('\t')?;
            let mode = meta.split(' ').next()?;
            Some((mode.to_owned(), path.to_owned()))
        })
        .collect()
}

/// The sorted regular files under `lab/` that git tracks (`git ls-files -s`).
/// Every index entry of any kind, symlinks and files deleted from the working
/// tree included, is checked for a forbidden path before anything is filtered
/// out. The working-tree walk is only a fallback outside a git checkout.
fn tracked_lab_files() -> Vec<PathBuf> {
    let out = std::process::Command::new("git")
        .args(["ls-files", "-s", "-z", "--", "lab"])
        .current_dir(root())
        .output();
    let mut files: Vec<PathBuf> = match out {
        Ok(o) if o.status.success() => {
            let entries = parse_index(&String::from_utf8_lossy(&o.stdout));
            for (mode, path) in &entries {
                assert!(
                    !forbidden_index_path(path),
                    "{path} (mode {mode}) is in the git index, but lab/.data and lab/.lock must never be committed"
                );
            }
            entries
                .into_iter()
                .filter(|(mode, _)| mode == "100644" || mode == "100755")
                .map(|(_, path)| root().join(path))
                .collect()
        }
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

/// The index check refuses `lab/.data` paths of every kind, however spelled.
#[test]
fn index_paths_under_lab_data_are_refused() {
    let raw = "100644 aaaa 0\tlab/up.sh\x00120000 bbbb 0\tlab/.data/link\x00100644 cccc 0\tlab/.DATA/x\x00100644 dddd 0\tlab/.lock\x00";
    let entries = parse_index(raw);
    assert_eq!(entries.len(), 4);
    let bad: Vec<&str> = entries
        .iter()
        .filter(|(_, p)| forbidden_index_path(p))
        .map(|(_, p)| p.as_str())
        .collect();
    assert_eq!(bad, ["lab/.data/link", "lab/.DATA/x", "lab/.lock"]);
    assert!(!forbidden_index_path("lab/up.sh"));
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

/// The scanner image: two stages, both pinned by digest, the Rust version of
/// `rust-toolchain.toml`, a locked release build, only the binary copied over,
/// a non-root user, and a `.dockerignore` that keeps secrets and state out.
#[test]
fn the_scanner_dockerfile_is_pinned_and_minimal() {
    let docker = read("lab/scanner/Dockerfile");
    let channel = read("rust-toolchain.toml")
        .lines()
        .find_map(|l| {
            l.strip_prefix("channel = \"")?
                .strip_suffix('"')
                .map(str::to_owned)
        })
        .expect("rust-toolchain.toml has a channel");
    let froms: Vec<&str> = docker
        .lines()
        .filter_map(|l| l.strip_prefix("FROM "))
        .collect();
    let mut problems = Vec::new();
    if froms.len() != 2 {
        problems.push(format!("{} FROM lines, expected 2", froms.len()));
    }
    for (n, from) in froms.iter().enumerate() {
        let image = from.split_whitespace().next().unwrap_or("");
        if !is_pinned(image) {
            problems.push(format!("FROM #{} is not pinned by digest", n + 1));
        }
    }
    let want_build = format!("rust:{channel}-slim-bookworm@sha256:");
    if !froms
        .first()
        .is_some_and(|f| f.starts_with(&want_build) && f.ends_with(" AS build"))
    {
        problems.push(format!(
            "the build stage must start FROM {want_build}... AS build"
        ));
    }
    if !froms
        .get(1)
        .is_some_and(|f| f.starts_with("gcr.io/distroless/cc-debian12:nonroot@sha256:"))
    {
        problems.push("the runtime stage must be distroless cc-debian12:nonroot".to_owned());
    }
    for needle in [
        "CARGO_BUILD_JOBS=8",
        "cargo build --locked --release -p guard-dog",
        "COPY --from=build /src/target/release/guard-dog /usr/local/bin/guard-dog",
        "USER nonroot",
        "ENTRYPOINT [\"/usr/local/bin/guard-dog\"]",
    ] {
        if !docker.contains(needle) {
            problems.push(format!("the Dockerfile lacks {needle:?}"));
        }
    }
    if docker.matches("COPY --from=").count() != 1 {
        problems.push("exactly one COPY --from (the binary) is allowed".to_owned());
    }
    for banned in [
        "\nADD ",
        "curl ",
        "wget ",
        "sudo",
        "--privileged",
        "USER root",
    ] {
        if docker.contains(banned) {
            problems.push(format!("the Dockerfile contains {banned:?}"));
        }
    }
    let ignore = read(".dockerignore");
    for line in [
        "target/",
        "lab/.data/",
        ".claude/",
        ".git/",
        "fixtures/private-setups/",
    ] {
        if !ignore.lines().any(|l| l == line) {
            problems.push(format!(".dockerignore lacks {line}"));
        }
    }
    assert!(problems.is_empty(), "problems:\n{}", problems.join("\n"));
}

/// `up.sh` proves identification without a credential, then each narrow
/// credential against the REST ports, and passes credentials to curl only on
/// stdin. A text check: the live run is the real one.
#[test]
fn up_sh_proves_rest_identification_and_keeps_credentials_off_the_command_line() {
    let up = read("lab/up.sh");
    let mut problems = Vec::new();
    for needle in [
        "WWW-Authenticate: Basic realm=\\\"jsonrpc\\\"",
        "https://lnd:8080/v1/state",
        "https://lnd:8080/v2/versioner/version",
        "https://lnd:8080/v1/balance/blockchain",
        "https://cln:3010/v1/getinfo",
        "https://cln:3010/v1/listfunds",
        "http://nutshell:3338/v1/info",
        "Accept: application/nostr+json",
        "-H @-",
        "Grpc-Metadata-macaroon",
        "Rune: ",
        "gdlabcanary-",
        "lab/.data/replies",
    ] {
        if !up.contains(needle) {
            problems.push(format!("up.sh lacks {needle:?}"));
        }
    }
    // A credential variable must never sit in a curl argument or an `-H` argument.
    for banned in ["-H \"Grpc", "-H \"Rune", "-H 'Rune", "-H 'Grpc", "--cacert"] {
        if up.contains(banned) {
            problems.push(format!("up.sh contains {banned:?}"));
        }
    }
    assert!(problems.is_empty(), "problems:\n{}", problems.join("\n"));
}
