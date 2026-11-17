//! The service catalog (`catalog/<id>.toml`), phase 1.4 step 1.
//!
//! Deterministic: no network, no Docker, no clock. Entries are read in sorted
//! order. The format is documented in `catalog/README.md`. The checks tie the
//! catalog to three sources already in the repo: the replies the lab recorded
//! (`fixtures/lab-recorded/manifest.toml`), Judge B's `[[product]]` table
//! (`fixtures/expected-matches.toml`) and the lab's services
//! (`lab/compose.yml`).
//!
//! Each rule is a function that returns `Err(message)`, so the mutation tests
//! can show the rule refuses a broken entry.

// Test-only crate: helper functions panic as failed checks. See expected_matches.rs.
#![allow(
    clippy::unwrap_used,
    clippy::expect_used,
    clippy::indexing_slicing,
    clippy::panic
)]

use std::collections::{BTreeMap, BTreeSet};
use std::fs;
use std::net::Ipv6Addr;
use std::path::{Path, PathBuf};
use std::sync::LazyLock;

use regex::{Regex, RegexBuilder};
use toml::{Table, Value};
use yaml_rust2::YamlLoader;

/// Judge B products with no catalog entry yet. Exact: the test fails when this
/// differs from the real gap in either direction, so it only shrinks by editing
/// it here. It shrinks as later pull requests add entries, and is empty once
/// PR 3 of the catalog plan lands.
const UNCATALOGUED: [&str; 10] = [
    "alby-hub",
    "btcpay-server",
    "coldcard",
    "fedimintd",
    "gatewayd",
    "lightning-terminal",
    "rtl",
    "tapd",
    "umbrelos",
    "xz-utils",
];

/// The ids catalogued when this list was written (PR 1). An id here must keep
/// its entry and can never appear in `UNCATALOGUED`, so the gap list cannot
/// grow back. Add to this list when entries land; never remove from it.
const CATALOGUED_BEFORE: [&str; 5] = [
    "bitcoin-core",
    "core-lightning",
    "lnd",
    "nutshell",
    "strfry",
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

/// Every call a catalog entry may make, exactly, as (form, descriptor): for
/// `cli` the argv joined by spaces, for `http` the method and path, for `rpc`
/// and `grpc` the method name. Anything else is refused, so adding a call is a
/// reviewed edit here. All of these only read. Every pair listed must be used.
const READ_ONLY_CALLS: [(&str, &str); 6] = [
    ("rpc", "getnetworkinfo"),
    ("grpc", "verrpc.Versioner/GetVersion"),
    ("grpc", "lnrpc.State/GetState"),
    ("cli", "lightning-cli getinfo"),
    ("http", "GET /"),
    ("http", "GET /v1/info"),
];

/// Programs an argv may never start with, whatever `recognize.binaries` says.
const NEVER_RUN: [&str; 22] = [
    "sh", "bash", "zsh", "dash", "ash", "env", "python", "python3", "perl", "ruby", "node",
    "busybox", "sudo", "su", "xargs", "awk", "sed", "find", "nc", "curl", "wget", "doas",
];

/// Ports two entries may both list, exactly, as (port, proto, reason).
const SHARED_PORTS: [(i64, &str, &str); 1] = [(
    9735,
    "tcp",
    "the Lightning peer-to-peer port is the same default for every Lightning node",
)];

/// Reviewed URL prefixes outside an entry's own repo, related repos and website,
/// as (entry id, field, prefix). Add one with a reason.
const OTHER_URLS: [(&str, &str, &str); 1] = [(
    "lnd",
    "advisories.feeds.url",
    // Lightning Labs' advisory site and Atom feed (spike d).
    "https://security.lightning.engineering/",
)];

/// Hosts that carry many projects: a website there must be exactly the repo.
const CODE_HOSTS: [&str; 3] = ["github.com", "gitlab.com", "codeberg.org"];

/// Shared page hosts: a website there must be the project's own subdomain,
/// `<owner>.<suffix>` with the owner from `upstream.repo`.
const PAGES_SUFFIXES: [&str; 6] = [
    "github.io",
    "gitlab.io",
    "codeberg.page",
    "pages.dev",
    "netlify.app",
    "vercel.app",
];

const KINDS: [&str; 6] = ["service", "platform", "device", "app", "miner", "package"];
const SOURCES: [&str; 7] = [
    "rpc",
    "grpc",
    "http",
    "nip11",
    "cli",
    "image-label",
    "platform-manifest",
];
const SCHEMES: [&str; 7] = [
    "semver",
    "bitcoin-core",
    "semver-beta",
    "major-minor",
    "git-describe",
    "calver",
    "opaque",
];
const PROBE_KINDS: [&str; 4] = ["nip11", "http", "rpc", "grpc"];
const PROTOS: [&str; 2] = ["tcp", "udp"];
const EXPOSURES: [&str; 3] = ["never-public", "lan", "public-ok"];
const PLATFORMS: [&str; 4] = ["umbrelos", "startos", "raspiblitz", "mynode"];
const VERSION_RULES: [&str; 3] = ["same", "image-tag", "differs"];
const FEED_KINDS: [&str; 4] = ["atom", "rss", "markdown-repo", "release-notes"];
const MACHINE_FEEDS: [&str; 3] = ["atom", "rss", "markdown-repo"];
const LEVELS: [&str; 5] = [
    "signed-multi",
    "signed-single",
    "tag-only",
    "unsigned",
    "unknown",
];
const REPRODUCIBLE: [&str; 3] = ["yes", "no", "unverified"];
const CERT_SOURCES: [&str; 3] = ["node-tls-cert", "system-roots", "pinned-in-config"];
/// Who runs a command-line call. Never root.
const RUN_AS: [&str; 2] = ["service-user-in-container", "service-user-on-host"];
/// Size limit for any regex that runs on untrusted text.
const REGEX_SIZE_LIMIT: usize = 100_000;
/// Longest pattern, and longest reply a pattern is ever run on (the README promises both).
const MAX_PATTERN: usize = 200;
const MAX_RAW: usize = 256;
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

// ---------- reading helpers ----------

fn check_keys(t: &Table, ctx: &str, required: &[&str], optional: &[&str]) -> Result<(), String> {
    for k in t.keys() {
        if !required.contains(&k.as_str()) && !optional.contains(&k.as_str()) {
            return Err(format!("unknown key `{k}` in {ctx}"));
        }
    }
    for k in required {
        if !t.contains_key(*k) {
            return Err(format!("missing key `{k}` in {ctx}"));
        }
    }
    Ok(())
}

fn string<'a>(t: &'a Table, k: &str, ctx: &str) -> Result<&'a str, String> {
    match t.get(k) {
        Some(Value::String(s)) => Ok(s),
        _ => Err(format!("{ctx}.{k} must be a string")),
    }
}

fn line<'a>(t: &'a Table, k: &str, ctx: &str) -> Result<&'a str, String> {
    let s = string(t, k, ctx)?;
    if s.is_empty() || s.chars().any(char::is_control) {
        return Err(format!("{ctx}.{k} must be one non-empty line"));
    }
    Ok(s)
}

fn one_of(t: &Table, k: &str, ctx: &str, allowed: &[&str]) -> Result<(), String> {
    let s = string(t, k, ctx)?;
    if allowed.contains(&s) {
        Ok(())
    } else {
        Err(format!("{ctx}.{k} must be one of {allowed:?}"))
    }
}

fn boolean(t: &Table, k: &str, ctx: &str) -> Result<bool, String> {
    match t.get(k) {
        Some(Value::Boolean(b)) => Ok(*b),
        _ => Err(format!("{ctx}.{k} must be true or false")),
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

fn strings_opt<'a>(t: &'a Table, k: &str, ctx: &str) -> Result<Vec<&'a str>, String> {
    if t.contains_key(k) {
        strings(t, k, ctx)
    } else {
        Ok(Vec::new())
    }
}

fn is_slug(s: &str) -> bool {
    static SLUG: LazyLock<Regex> =
        LazyLock::new(|| Regex::new(r"^[a-z0-9]+(-[a-z0-9]+)*$").unwrap());
    s.len() <= 40 && SLUG.is_match(s)
}

fn is_date(v: &Value) -> bool {
    matches!(v, Value::Datetime(d) if d.date.is_some() && d.time.is_none() && d.offset.is_none())
}

static INLINE_FLAGS: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\(\?[a-zA-Z-]+[:)]").unwrap());

/// A catalog regex that runs on untrusted text. It must start with `^` and end
/// with an unescaped `$`, be at most 200 characters, and carry no inline flags
/// (`(?m)`, `(?s)`, `(?x)` and so on). It is compiled as `\A(?:pattern)\z`, so
/// an alternation inside it can never match part of a reply, and with a size limit.
fn untrusted_regex(pattern: &str) -> Result<Regex, String> {
    if pattern.len() < 2 || !pattern.starts_with('^') || !pattern.ends_with('$') {
        return Err(format!("pattern must be anchored (^...$): {pattern}"));
    }
    let slashes = pattern[..pattern.len() - 1]
        .chars()
        .rev()
        .take_while(|c| *c == '\\')
        .count();
    if slashes % 2 == 1 {
        return Err(format!(
            "pattern ends in an escaped $, not an anchor: {pattern}"
        ));
    }
    if pattern.len() > MAX_PATTERN {
        return Err(format!("pattern is longer than {MAX_PATTERN} characters"));
    }
    if INLINE_FLAGS.is_match(pattern) {
        return Err(format!("pattern must not use inline flags: {pattern}"));
    }
    // The bare pattern must compile on its own first: a stray `)` would otherwise
    // close the wrapper below and let the rest of the pattern run unanchored.
    RegexBuilder::new(pattern)
        .size_limit(REGEX_SIZE_LIMIT)
        .build()
        .map_err(|e| format!("pattern does not compile on its own within the size limit: {e}"))?;
    RegexBuilder::new(&format!(r"\A(?:{pattern})\z"))
        .size_limit(REGEX_SIZE_LIMIT)
        .build()
        .map_err(|e| format!("pattern does not compile within the size limit: {e}"))
}

// ---------- URLs ----------

fn internal_host(host: &str) -> bool {
    host == "localhost"
        || [
            ".internal",
            ".local",
            ".lan",
            ".localhost",
            ".home.arpa",
            ".test",
            // Names that resolve to a loopback or private address by design.
            "localtest.me",
            "lvh.me",
            "nip.io",
            "sslip.io",
            "xip.io",
        ]
        .iter()
        .any(|s| host.ends_with(s))
        || host.chars().all(|c| c.is_ascii_digit() || c == '.')
}

/// Splits an https URL into (host, path). Refuses anything else, and internal names.
fn https_parts(url: &str) -> Result<(&str, &str), String> {
    let rest = url
        .strip_prefix("https://")
        .ok_or(format!("URL must be https: {url}"))?;
    if rest.contains(['?', '#', '@', ' ']) || url.chars().any(char::is_control) {
        return Err(format!(
            "URL must have no credentials, query, fragment or spaces: {url}"
        ));
    }
    let (host, path) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
    let host_ok = !host.is_empty()
        && host.contains('.')
        && host
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '-');
    if !host_ok || path.contains("..") {
        return Err(format!(
            "URL host must be a lower-case name, no port: {url}"
        ));
    }
    if internal_host(host) {
        return Err(format!(
            "URL names an internal host or an IP address: {url}"
        ));
    }
    Ok((host, path))
}

/// Is `url` equal to `base` or below it (a whole path segment, not a prefix of a name)?
fn under(url: &str, base: &str) -> bool {
    let base = base.trim_end_matches('/');
    url == base || url.strip_prefix(base).is_some_and(|r| r.starts_with('/'))
}

/// A repo URL is `https://host/owner/repo`, nothing more.
fn check_repo_url(url: &str) -> Result<(), String> {
    let (_, path) = https_parts(url)?;
    let segs: Vec<&str> = path.trim_matches('/').split('/').collect();
    if segs.len() != 2 || segs.iter().any(|s| s.is_empty()) || path.ends_with('/') {
        return Err(format!("repo URL must be https://host/owner/repo: {url}"));
    }
    Ok(())
}

/// A website may not sit on a shared code host unless it is exactly the repo.
fn check_website(repo: &str, site: &str) -> Result<(), String> {
    let (host, _) = https_parts(site)?;
    if CODE_HOSTS.contains(&host) && site.trim_end_matches('/') != repo {
        return Err(format!(
            "website on a shared code host must be exactly upstream.repo: {site}"
        ));
    }
    let owner = repo
        .strip_prefix("https://")
        .and_then(|r| r.split('/').nth(1))
        .unwrap_or("")
        .to_ascii_lowercase();
    for suffix in PAGES_SUFFIXES {
        let own = format!("{owner}.{suffix}");
        if (host == suffix || host.ends_with(&format!(".{suffix}"))) && host != own {
            return Err(format!(
                "website on a shared pages host must be {own} (the upstream owner), not {host}"
            ));
        }
    }
    Ok(())
}

/// A feed, policy, key, source or advisory URL must sit under the entry's own
/// repo (same owner and repo), a listed related repo, its website, or a
/// reviewed (entry, field, prefix) exception.
fn check_under_upstream(id: &str, up: &Table, field: &str, url: &str) -> Result<(), String> {
    https_parts(url)?;
    let mut bases = vec![string(up, "repo", "upstream")?];
    bases.extend(strings_opt(up, "related_repos", "upstream")?);
    if let Some(Value::String(site)) = up.get("website") {
        bases.push(site);
    }
    bases.extend(
        OTHER_URLS
            .iter()
            .filter(|(i, f, _)| *i == id && *f == field)
            .map(|(_, _, p)| *p),
    );
    if bases.iter().any(|b| under(url, b)) {
        Ok(())
    } else {
        Err(format!(
            "{field} is not under upstream.repo, related_repos or website: {url}"
        ))
    }
}

/// A `source` is a file in the repo, or an https URL under the entry's own upstream.
fn check_source(id: &str, up: &Table, field: &str, src: &str) -> Result<(), String> {
    if src.starts_with("https://") {
        check_under_upstream(id, up, field, src)
    } else if src.contains("..") || src.starts_with('/') || !root().join(src).is_file() {
        Err(format!(
            "{field} must be a file in the repo or a URL under the upstream: {src}"
        ))
    } else {
        Ok(())
    }
}

// ---------- calls, probes and credentials ----------

static HOST_LIKE: LazyLock<Regex> =
    LazyLock::new(|| Regex::new(r"(?i)\b[a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+)+\b").unwrap());

/// Text in a call, probe or credential never names a place: no scheme, host,
/// user info, `..`, link-local or metadata address, or onion address. Method
/// names may contain dots (`verrpc.Versioner/GetVersion`), so they skip the
/// host-name test and are held to the exact READ_ONLY_CALLS list instead.
fn no_endpoint_text(label: &str, s: &str, host_test: bool) -> Result<(), String> {
    let lower = s.to_ascii_lowercase();
    let bad = lower.contains("://")
        || s.contains('@')
        || s.contains("..")
        || lower.contains(".onion")
        || lower.contains("169.254.")
        || lower.contains("fe80:")
        || lower.contains("metadata")
        || (host_test && HOST_LIKE.is_match(s));
    if bad {
        return Err(format!(
            "{label} must not name a scheme, host, user info, `..`, link-local or onion address: {s}"
        ));
    }
    Ok(())
}

fn call_form(kind: &str) -> &'static str {
    match kind {
        "cli" => "cli",
        "http" | "nip11" => "http",
        "rpc" => "rpc",
        "grpc" => "grpc",
        _ => "other",
    }
}

/// The call as READ_ONLY_CALLS spells it.
fn descriptor(t: &Table, form: &str) -> Option<String> {
    match form {
        "cli" => Some(
            t.get("argv")?
                .as_array()?
                .iter()
                .filter_map(Value::as_str)
                .collect::<Vec<_>>()
                .join(" "),
        ),
        "http" => Some(format!("GET {}", t.get("path")?.as_str()?)),
        "rpc" | "grpc" => Some(t.get("method")?.as_str()?.to_string()),
        _ => None,
    }
}

/// Checks the structured call keys (`argv`, `run_as`, `method`, `path`, `accept`)
/// present in `t` for a call of this form, and that the call is in READ_ONLY_CALLS.
/// Never a shell string.
fn check_call(t: &Table, form: &str, ctx: &str, binaries: &[&str]) -> Result<(), String> {
    let has = |k: &str| t.contains_key(k);
    let allowed: &[&str] = match form {
        "cli" => &["argv", "run_as"],
        "http" => &["method", "path", "accept"],
        "rpc" | "grpc" => &["method"],
        _ => &[],
    };
    for k in ["argv", "run_as", "method", "path", "accept"] {
        if has(k) && !allowed.contains(&k) {
            return Err(format!("{ctx}.{k} is not allowed for a {form} call"));
        }
    }
    match form {
        "cli" => {
            let argv = strings(t, "argv", ctx)?;
            let Some(first) = argv.first() else {
                return Err(format!("{ctx}.argv must not be empty"));
            };
            if first.contains('/') {
                return Err(format!(
                    "{ctx}.argv[0] must be a bare program name: {first}"
                ));
            }
            if NEVER_RUN.contains(first) {
                return Err(format!(
                    "{ctx}.argv[0] must never run a shell or interpreter: {first}"
                ));
            }
            if !binaries.contains(first) {
                return Err(format!(
                    "{ctx}.argv[0] `{first}` is not in recognize.binaries"
                ));
            }
            for a in &argv {
                let bad = a.is_empty()
                    || a.chars().any(|c| {
                        c.is_whitespace() || c.is_control() || ";|&$`<>(){}*?~\\\"'!#".contains(c)
                    });
                if bad {
                    return Err(format!(
                        "{ctx}.argv items are plain words, never shell: {a}"
                    ));
                }
                no_endpoint_text(&format!("{ctx}.argv"), a, true)?;
            }
            one_of(t, "run_as", ctx, &RUN_AS)?;
        }
        "http" => {
            if string(t, "method", ctx)? != "GET" {
                return Err(format!("{ctx}.method must be GET (read-only)"));
            }
            let path = string(t, "path", ctx)?;
            static PATH: LazyLock<Regex> =
                LazyLock::new(|| Regex::new(r"^/[A-Za-z0-9_~/-]*$").unwrap());
            if !PATH.is_match(path) || path.contains("//") {
                return Err(format!(
                    "{ctx}.path must be a local path like /v1/info: {path}"
                ));
            }
            if has("accept") {
                static MIME: LazyLock<Regex> =
                    LazyLock::new(|| Regex::new(r"^[a-z]+/[a-z0-9+-]+$").unwrap());
                if !MIME.is_match(string(t, "accept", ctx)?) {
                    return Err(format!("{ctx}.accept must be a media type"));
                }
            }
        }
        "rpc" | "grpc" => {
            static NAME: LazyLock<Regex> =
                LazyLock::new(|| Regex::new(r"^[A-Za-z0-9_./]{1,80}$").unwrap());
            let m = string(t, "method", ctx)?;
            if !NAME.is_match(m) {
                return Err(format!("{ctx}.method must be a method name: {m}"));
            }
            no_endpoint_text(&format!("{ctx}.method"), m, false)?;
        }
        _ => {}
    }
    if let Some(d) = descriptor(t, form)
        && !READ_ONLY_CALLS.iter().any(|(f, x)| *f == form && *x == d)
    {
        return Err(format!(
            "{ctx}: the {form} call `{d}` is not in READ_ONLY_CALLS"
        ));
    }
    Ok(())
}

/// The reply field a call reads: a plain dotted name.
fn check_field(t: &Table, ctx: &str) -> Result<(), String> {
    static FIELD: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"^[A-Za-z0-9_.]{1,64}$").unwrap());
    let f = line(t, "field", ctx)?;
    if !FIELD.is_match(f) || f.contains("..") {
        return Err(format!(
            "{ctx}.field must match [A-Za-z0-9_.]{{1,64}} with no `..`: {f}"
        ));
    }
    Ok(())
}

// ---------- secret shapes ----------

static SECRET_SHAPES: LazyLock<Vec<(&str, Regex)>> = LazyLock::new(|| {
    let shapes: [(&str, &str); 14] = [
        (
            "extended key (xpub/xprv family)",
            r"[xyztuvXYZTUV](?:pub|prv)[1-9A-HJ-NP-Za-km-z]{20,}",
        ),
        ("nsec", r"nsec1[02-9ac-hj-np-z]{20,}"),
        (
            "12 or more seed-phrase-like words",
            r"\b[a-z]{3,8}(?: [a-z]{3,8}){11,}\b",
        ),
        ("long hex (macaroon, key or hash)", r"[0-9a-fA-F]{64,}"),
        ("base64 macaroon", r"Ag[EF][A-Za-z0-9+/_=-]{30,}"),
        ("onion address", r"(?i)\.onion\b"),
        ("private key block", r"-----BEGIN [A-Z ]*PRIVATE KEY"),
        ("Lightning invoice", r"\bln(?:bc|tb|bcrt)[0-9]"),
        ("Cashu token", r"\bcashu[AB][A-Za-z0-9_-]{10,}"),
        (
            "GitHub token",
            r"\b(?:ghp|gho|ghs|ghu)_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{20,}",
        ),
        ("AWS access key", r"\bAKIA[0-9A-Z]{16}\b"),
        ("API key (sk-)", r"\bsk-[A-Za-z0-9_-]{20,}"),
        ("IPv4 address", r"\b\d{1,3}(?:\.\d{1,3}){3}\b"),
        ("IPv6 candidate", r"[0-9A-Fa-f:]{2,}"),
    ];
    shapes
        .iter()
        .map(|(n, p)| (*n, Regex::new(p).unwrap()))
        .collect()
});

static FORTY_HEX: LazyLock<Regex> = LazyLock::new(|| Regex::new(r"\b[0-9a-fA-F]{40}\b").unwrap());

/// Is this token a real IPv6 address outside the documentation range 2001:db8::/32?
fn is_public_ipv6(token: &str) -> bool {
    if token.matches(':').count() < 2 {
        return false;
    }
    match token.parse::<Ipv6Addr>() {
        Ok(a) => {
            let s = a.segments();
            !(s[0] == 0x2001 && s[1] == 0x0db8)
        }
        Err(_) => false,
    }
}

fn collect_strings(path: &str, v: &Value, out: &mut Vec<(String, String)>) {
    match v {
        Value::String(s) => out.push((path.to_string(), s.clone())),
        Value::Array(a) => {
            for (i, x) in a.iter().enumerate() {
                collect_strings(&format!("{path}[{i}]"), x, out);
            }
        }
        Value::Table(t) => {
            for (k, x) in t {
                collect_strings(&format!("{path}.{k}"), x, out);
            }
        }
        _ => {}
    }
}

fn is_fingerprint_path(path: &str) -> bool {
    path.starts_with(".signing.keys[") && path.ends_with("].fingerprint")
}

fn no_secret_shapes(t: &Table) -> Result<(), String> {
    let mut all = Vec::new();
    for (k, v) in t {
        collect_strings(&format!(".{k}"), v, &mut all);
    }
    for (path, s) in all {
        for (name, re) in SECRET_SHAPES.iter() {
            for m in re.find_iter(&s) {
                let flagged = match *name {
                    "IPv6 candidate" => is_public_ipv6(m.as_str()),
                    "IPv4 address" => !["192.0.2.", "198.51.100.", "203.0.113."]
                        .iter()
                        .any(|p| m.as_str().starts_with(p)),
                    _ => true,
                };
                if flagged {
                    let name = if *name == "IPv6 candidate" {
                        "IPv6 address"
                    } else {
                        name
                    };
                    return Err(format!("{path} has a secret shape: {name}"));
                }
            }
        }
        if FORTY_HEX.is_match(&s) && !is_fingerprint_path(&path) {
            return Err(format!(
                "{path} has a secret shape: 40-hex outside signing.keys.fingerprint"
            ));
        }
    }
    Ok(())
}

// ---------- images ----------

/// The one image-name normaliser: lower case, no digest, no tag, `docker.io/`
/// when no registry is given, and `library/` for Docker Hub's single names. A
/// registry may carry a port (`localhost:5000/a/b`). A trailing `*` (a pattern) is kept.
fn normalise_image(image: &str) -> String {
    let (body, star) = match image.strip_suffix('*') {
        Some(b) => (b, "*"),
        None => (image, ""),
    };
    let lower = body.to_ascii_lowercase();
    let no_digest = lower.split('@').next().unwrap_or(&lower);
    let name = match no_digest.rsplit_once(':') {
        Some((n, tag)) if !tag.contains('/') => n,
        _ => no_digest,
    };
    let mut parts: Vec<&str> = name.split('/').collect();
    let first = parts[0];
    let has_registry = parts.len() > 1 && (first.contains('.') || first.contains(':'));
    if has_registry {
        if first == "index.docker.io" || first == "registry-1.docker.io" {
            parts[0] = "docker.io";
        }
    } else {
        parts.insert(0, "docker.io");
    }
    if parts[0] == "docker.io" && parts.len() == 2 {
        parts.insert(1, "library");
    }
    format!("{}{star}", parts.join("/"))
}

fn check_image_pattern(img: &str) -> Result<(), String> {
    let body = img.strip_suffix('*').unwrap_or(img);
    let tail_has_colon = body
        .split_once('/')
        .is_some_and(|(_, rest)| rest.contains(':'));
    if body.contains('*')
        || img.contains(['@', ' '])
        || tail_has_colon
        || normalise_image(img) != img
    {
        return Err(format!(
            "image `{img}` must be in normalised form docker.io/namespace/repo, no tag or digest, `*` only at the end"
        ));
    }
    Ok(())
}

// ---------- one entry ----------

/// Every per-file rule. Returns the parsed table.
fn validate(stem: &str, text: &str) -> Result<Table, String> {
    let t: Table = toml::from_str(text).map_err(|e| format!("{stem}: not valid TOML: {e}"))?;
    check_entry(&t, stem).map_err(|e| format!("{stem}: {e}"))?;
    no_secret_shapes(&t).map_err(|e| format!("{stem}: {e}"))?;
    Ok(t)
}

fn check_entry(t: &Table, stem: &str) -> Result<(), String> {
    check_keys(
        t,
        "the entry",
        &[
            "format",
            "id",
            "name",
            "kind",
            "aliases",
            "summary",
            "money",
            "licence",
            "upstream",
            "recognize",
            "version",
            "advisories",
            "signing",
            "review",
        ],
        &["fork_of", "bundles", "platform_map"],
    )?;
    if t.get("format") != Some(&Value::Integer(1)) {
        return Err("format must be 1".into());
    }
    let id = string(t, "id", "entry")?;
    if !is_slug(id) {
        return Err(format!("id `{id}` must be a slug of at most 40 characters"));
    }
    if id != stem {
        return Err(format!("id `{id}` must equal the file name `{stem}.toml`"));
    }
    line(t, "name", "entry")?;
    one_of(t, "kind", "entry", &KINDS)?;
    for a in strings(t, "aliases", "entry")? {
        if !is_slug(a) {
            return Err(format!("alias `{a}` must be a slug"));
        }
    }
    line(t, "summary", "entry")?;
    boolean(t, "money", "entry")?;
    line(t, "licence", "entry")?;
    if t.contains_key("fork_of") && !is_slug(string(t, "fork_of", "entry")?) {
        return Err("fork_of must be a slug".into());
    }
    for b in strings_opt(t, "bundles", "entry")? {
        if !is_slug(b) {
            return Err(format!("bundles entry `{b}` must be a slug"));
        }
    }

    // [review] is read first: open `todo` items excuse some gaps below.
    let rv = table(t, "review", "entry")?;
    check_keys(rv, "review", &["last_reviewed", "sources", "todo"], &[])?;
    let todo = strings(rv, "todo", "review")?;
    let has_todo = |prefix: &str| todo.iter().any(|i| i.starts_with(prefix));

    // [upstream]
    let up = table(t, "upstream", "entry")?;
    check_keys(
        up,
        "upstream",
        &["repo"],
        &[
            "website",
            "security_policy",
            "release_feed",
            "related_repos",
        ],
    )?;
    let repo = string(up, "repo", "upstream")?;
    check_repo_url(repo)?;
    let (repo_host, _) = https_parts(repo)?;
    for r in strings_opt(up, "related_repos", "upstream")? {
        check_repo_url(r)?;
        if r == repo {
            return Err("related_repos must not repeat upstream.repo".into());
        }
        if https_parts(r)?.0 != repo_host {
            return Err(format!(
                "related_repos must be on the same code host as the repo: {r}"
            ));
        }
    }
    if up.contains_key("website") {
        check_website(repo, string(up, "website", "upstream")?)?;
    }
    for f in ["security_policy", "release_feed"] {
        if up.contains_key(f) {
            check_under_upstream(id, up, f, string(up, f, "upstream")?)?;
        }
    }

    // [recognize]
    let rec = table(t, "recognize", "entry")?;
    check_keys(
        rec,
        "recognize",
        &["images", "binaries", "units"],
        &["ports", "probes"],
    )?;
    for img in strings(rec, "images", "recognize")? {
        check_image_pattern(img)?;
    }
    let binaries = strings(rec, "binaries", "recognize")?;
    if binaries.is_empty() && !has_todo("binaries:") {
        return Err("recognize.binaries is empty and review.todo has no `binaries:` item".into());
    }
    if strings(rec, "units", "recognize")?.is_empty() && !has_todo("units:") {
        return Err("recognize.units is empty and review.todo has no `units:` item".into());
    }
    let mut ports: Vec<i64> = Vec::new();
    for p in tables(rec, "ports", "recognize")? {
        check_keys(
            p,
            "recognize.ports",
            &["port", "proto", "what", "exposure"],
            &["source"],
        )?;
        match p.get("port") {
            Some(Value::Integer(n)) if (1..=65535).contains(n) => ports.push(*n),
            _ => return Err("recognize.ports.port must be 1 to 65535".into()),
        }
        one_of(p, "proto", "recognize.ports", &PROTOS)?;
        line(p, "what", "recognize.ports")?;
        one_of(p, "exposure", "recognize.ports", &EXPOSURES)?;
        if p.contains_key("source") {
            check_source(
                id,
                up,
                "recognize.ports.source",
                line(p, "source", "recognize.ports")?,
            )?;
        }
    }
    let version_port = t
        .get("version")
        .and_then(Value::as_table)
        .is_some_and(|v| v.contains_key("endpoint_port"));
    for p in tables(rec, "probes", "recognize")? {
        check_keys(
            p,
            "recognize.probes",
            &["kind", "method"],
            &["path", "accept", "port", "field", "match"],
        )?;
        one_of(p, "kind", "recognize.probes", &PROBE_KINDS)?;
        let kind = string(p, "kind", "recognize.probes")?;
        check_call(p, call_form(kind), "recognize.probes", &binaries)?;
        match p.get("port") {
            Some(Value::Integer(n)) if ports.contains(n) => {}
            Some(_) => return Err("recognize.probes.port must be one of recognize.ports".into()),
            None if version_port || has_todo("ports:") => {}
            None => {
                return Err(
                    "recognize.probes needs a port (or version.endpoint_port, or a `ports:` todo)"
                        .into(),
                );
            }
        }
        if p.contains_key("field") != p.contains_key("match") {
            return Err("recognize.probes: field and match go together".into());
        }
        if p.contains_key("match") {
            check_field(p, "recognize.probes")?;
            untrusted_regex(string(p, "match", "recognize.probes")?)?;
        }
    }

    // [version]
    let v = table(t, "version", "entry")?;
    check_keys(
        v,
        "version",
        &[
            "source",
            "call",
            "credential",
            "regex",
            "scheme",
            "examples",
        ],
        &["endpoint_port", "tls"],
    )?;
    one_of(v, "source", "version", &SOURCES)?;
    let source = string(v, "source", "version")?;
    let call = table(v, "call", "version")?;
    check_keys(
        call,
        "version.call",
        &["field"],
        &["argv", "run_as", "method", "path", "accept"],
    )?;
    check_field(call, "version.call")?;
    check_call(call, call_form(source), "version.call", &binaries)?;
    no_endpoint_text(
        "version.credential",
        line(v, "credential", "version")?,
        true,
    )?;
    one_of(v, "scheme", "version", &SCHEMES)?;
    // A network source names its port, or the entry says in `todo` that ports are open.
    if matches!(source, "rpc" | "grpc" | "http" | "nip11") {
        match v.get("endpoint_port") {
            Some(Value::Integer(p)) if ports.contains(p) => {}
            Some(_) => return Err("version.endpoint_port must be one of recognize.ports".into()),
            None if has_todo("ports:") => {}
            None => {
                return Err(
                    "version.endpoint_port is missing and review.todo has no `ports:` item".into(),
                );
            }
        }
    } else if v.contains_key("endpoint_port") {
        return Err("version.endpoint_port is only for network sources".into());
    }
    // TLS: a grpc source says where the certificate comes from and the name it must
    // carry. There is no way to switch verification off: unknown keys fail.
    if source == "grpc" {
        let tls = table(v, "tls", "version")?;
        check_keys(tls, "version.tls", &["cert_source", "server_name"], &[])?;
        one_of(tls, "cert_source", "version.tls", &CERT_SOURCES)?;
        let name = line(tls, "server_name", "version.tls")?;
        no_endpoint_text("version.tls.server_name", name, true)?;
        // A bare local name: `localhost` or this entry's own id, never a public DNS name.
        if name != "localhost" && name != id {
            return Err(format!(
                "version.tls.server_name must be `localhost` or the entry id, not `{name}`"
            ));
        }
    } else if v.contains_key("tls") {
        return Err("version.tls is only for grpc sources".into());
    }
    let re = version_regex(v)?;
    let examples = tables(v, "examples", "version")?;
    if examples.is_empty() {
        return Err("version.examples needs at least one real reply".into());
    }
    for e in examples {
        check_keys(e, "version.examples", &["raw", "version", "source"], &[])?;
        check_source(
            id,
            up,
            "version.examples.source",
            line(e, "source", "version.examples")?,
        )?;
        let raw = string(e, "raw", "version.examples")?;
        let want = line(e, "version", "version.examples")?;
        let got = extract(&re, raw);
        if got.as_deref() != Some(want) {
            return Err(format!(
                "version.regex on example `{raw}` gives {got:?}, expected `{want}`"
            ));
        }
    }

    // [[platform_map]]
    for m in tables(t, "platform_map", "entry")? {
        check_keys(
            m,
            "platform_map",
            &["platform", "app_id", "version_rule"],
            &["note"],
        )?;
        one_of(m, "platform", "platform_map", &PLATFORMS)?;
        line(m, "app_id", "platform_map")?;
        one_of(m, "version_rule", "platform_map", &VERSION_RULES)?;
    }

    // [advisories]
    let adv = table(t, "advisories", "entry")?;
    check_keys(
        adv,
        "advisories",
        &["osv_packages", "ghsa", "feeds"],
        &["blind_spot"],
    )?;
    for p in strings(adv, "osv_packages", "advisories")? {
        let ok = p
            .split_once(' ')
            .is_some_and(|(eco, name)| !eco.is_empty() && !name.is_empty() && !name.contains(' '));
        if !ok {
            return Err(format!("osv package `{p}` must be `<ECOSYSTEM> <name>`"));
        }
    }
    let ghsa = boolean(adv, "ghsa", "advisories")?;
    let mut machine_feed = false;
    for f in tables(adv, "feeds", "advisories")? {
        check_keys(f, "advisories.feeds", &["kind", "url"], &[])?;
        one_of(f, "kind", "advisories.feeds", &FEED_KINDS)?;
        machine_feed |= MACHINE_FEEDS.contains(&string(f, "kind", "advisories.feeds")?);
        check_under_upstream(
            id,
            up,
            "advisories.feeds.url",
            string(f, "url", "advisories.feeds")?,
        )?;
    }
    if adv.contains_key("blind_spot") {
        line(adv, "blind_spot", "advisories")?;
    } else if !ghsa && !machine_feed {
        return Err("advisories: no GHSA and no feed a machine can read needs a blind_spot".into());
    }

    // [signing]
    let sg = table(t, "signing", "entry")?;
    check_keys(
        sg,
        "signing",
        &["level"],
        &[
            "method",
            "keys_url",
            "min_signatures",
            "reproducible",
            "images_signed",
            "keys",
        ],
    )?;
    one_of(sg, "level", "signing", &LEVELS)?;
    if sg.contains_key("method") {
        line(sg, "method", "signing")?;
    }
    if sg.contains_key("keys_url") {
        check_under_upstream(id, up, "keys_url", string(sg, "keys_url", "signing")?)?;
    }
    if sg.contains_key("min_signatures")
        && !matches!(sg.get("min_signatures"), Some(Value::Integer(n)) if *n >= 1)
    {
        return Err("signing.min_signatures must be a whole number from 1".into());
    }
    if string(sg, "level", "signing")? == "signed-multi"
        && !sg.contains_key("min_signatures")
        && !has_todo("signing.min_signatures")
    {
        return Err(
            "signed-multi needs signing.min_signatures or a `signing.min_signatures` todo".into(),
        );
    }
    if sg.contains_key("reproducible") {
        one_of(sg, "reproducible", "signing", &REPRODUCIBLE)?;
    }
    if sg.contains_key("images_signed") {
        boolean(sg, "images_signed", "signing")?;
    }
    for k in tables(sg, "keys", "signing")? {
        check_keys(k, "signing.keys", &["who", "fingerprint", "checked"], &[])?;
        line(k, "who", "signing.keys")?;
        let fp = string(k, "fingerprint", "signing.keys")?;
        if fp.len() != 40 || !fp.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err("signing.keys.fingerprint must be 40 hex characters".into());
        }
        if !k.get("checked").is_some_and(is_date) {
            return Err("signing.keys.checked must be a date".into());
        }
    }

    // rest of [review]
    if !rv.get("last_reviewed").is_some_and(is_date) {
        return Err("review.last_reviewed must be a date".into());
    }
    let sources = strings(rv, "sources", "review")?;
    if sources.is_empty() {
        return Err("review.sources must cite at least one page".into());
    }
    for s in sources {
        https_parts(s)?;
    }
    for item in todo {
        if item.is_empty() || item.chars().any(char::is_control) {
            return Err("review.todo items must be one non-empty line".into());
        }
    }
    Ok(())
}

/// The entry's version regex: anchored, length-limited, bounded, with a `version` group.
fn version_regex(v: &Table) -> Result<Regex, String> {
    let re = untrusted_regex(string(v, "regex", "version")?)
        .map_err(|e| format!("version.regex: {e}"))?;
    if !re.capture_names().flatten().any(|n| n == "version") {
        return Err("version.regex needs a group named `version`".into());
    }
    Ok(re)
}

/// Runs a version regex on a raw reply. Replies over `MAX_RAW` bytes are refused.
fn extract(re: &Regex, raw: &str) -> Option<String> {
    if raw.len() > MAX_RAW {
        return None;
    }
    re.captures(raw)?
        .name("version")
        .map(|m| m.as_str().to_string())
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

/// No entry's version regex or probe pattern may match another entry's recorded or example reply.
fn check_negative(entries: &BTreeMap<String, Table>, rec: &[Recorded]) -> Result<(), String> {
    let mut raws: Vec<(String, String)> =
        rec.iter().map(|r| (r.id.clone(), r.raw.clone())).collect();
    for (id, e) in entries {
        for ex in tables(table(e, "version", id)?, "examples", id)? {
            raws.push((id.clone(), string(ex, "raw", id)?.to_string()));
        }
    }
    for (id, e) in entries {
        let mut patterns = vec![("version regex", version_regex(table(e, "version", id)?)?)];
        for p in tables(table(e, "recognize", id)?, "probes", id)? {
            if let Some(Value::String(m)) = p.get("match") {
                patterns.push(("probe pattern", untrusted_regex(m)?));
            }
        }
        for (what, re) in &patterns {
            for (owner, raw) in &raws {
                if owner != id && re.is_match(raw) {
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

/// Images are disjoint across entries; ports are too, except the exact SHARED_PORTS.
fn check_disjoint(entries: &BTreeMap<String, Table>) -> Result<(), String> {
    let mut images: Vec<(String, String)> = Vec::new();
    let mut ports: BTreeMap<(i64, String), Vec<String>> = BTreeMap::new();
    for (id, e) in entries {
        let rec = table(e, "recognize", id)?;
        for i in strings(rec, "images", id)? {
            images.push((i.to_string(), id.clone()));
        }
        for p in tables(rec, "ports", id)? {
            let key = (
                p["port"].as_integer().unwrap(),
                string(p, "proto", id)?.to_string(),
            );
            ports.entry(key).or_default().push(id.clone());
        }
    }
    for (i, (a, ida)) in images.iter().enumerate() {
        for (b, idb) in &images[i + 1..] {
            let (sa, sb) = (a.trim_end_matches('*'), b.trim_end_matches('*'));
            let overlap = match (a.ends_with('*'), b.ends_with('*')) {
                (false, false) => a == b,
                (true, false) => sb.starts_with(sa),
                (false, true) => sa.starts_with(sb),
                (true, true) => sa.starts_with(sb) || sb.starts_with(sa),
            };
            if overlap && ida != idb {
                return Err(format!(
                    "recognize.images of `{ida}` and `{idb}` overlap: {a} and {b}"
                ));
            }
        }
    }
    let shared: BTreeSet<(i64, String)> = ports
        .iter()
        .filter(|(_, ids)| ids.len() > 1)
        .map(|(k, _)| k.clone())
        .collect();
    let allowed: BTreeSet<(i64, String)> = SHARED_PORTS
        .iter()
        .map(|(p, proto, _)| (*p, proto.to_string()))
        .collect();
    if shared != allowed {
        return Err(format!(
            "ports listed by more than one entry {shared:?} differ from SHARED_PORTS {allowed:?}"
        ));
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

fn check_unique(entries: &BTreeMap<String, Table>) -> Result<(), String> {
    let mut seen: BTreeMap<String, String> = BTreeMap::new();
    for (id, e) in entries {
        let names = std::iter::once(id.as_str()).chain(strings(e, "aliases", id)?);
        for n in names {
            if let Some(other) = seen.insert(n.to_string(), id.clone()) {
                return Err(format!("`{n}` is used by both `{other}` and `{id}`"));
            }
        }
    }
    Ok(())
}

/// `fork_of` and `bundles` name existing entries, never themselves, never in a cycle.
fn check_links(entries: &BTreeMap<String, Table>) -> Result<(), String> {
    let mut edges: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for (id, e) in entries {
        let mut targets: Vec<&str> = Vec::new();
        if e.contains_key("fork_of") {
            targets.push(string(e, "fork_of", id)?);
        }
        targets.extend(strings_opt(e, "bundles", id)?);
        for t in &targets {
            if t == id {
                return Err(format!("{id}: fork_of or bundles names itself"));
            }
            if !entries.contains_key(*t) {
                return Err(format!(
                    "{id}: fork_of or bundles names `{t}`, which is not an entry"
                ));
            }
        }
        edges.insert(id, targets);
    }
    // Depth-first search; 1 = on the current path, 2 = finished.
    fn visit<'a>(
        n: &'a str,
        edges: &BTreeMap<&'a str, Vec<&'a str>>,
        state: &mut BTreeMap<&'a str, u8>,
    ) -> Result<(), String> {
        match state.get(n) {
            Some(1) => return Err(format!("fork_of or bundles has a cycle through `{n}`")),
            Some(_) => return Ok(()),
            None => {}
        }
        state.insert(n, 1);
        for next in edges.get(n).map(Vec::as_slice).unwrap_or_default() {
            visit(next, edges, state)?;
        }
        state.insert(n, 2);
        Ok(())
    }
    let mut state = BTreeMap::new();
    for id in entries.keys() {
        visit(id, &edges, &mut state)?;
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
    check_links(&all).unwrap();
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
    println!("{} entries, {todo} open todo items", all.len());
}

#[test]
fn catalog_ids_and_aliases_are_unique() {
    check_unique(&entries()).unwrap();
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
        .flat_map(|e| e["recognize"]["ports"].as_array().into_iter().flatten())
        .filter(|p| p.get("source").and_then(Value::as_str) == Some(LAB_FILE))
        .count();
    assert!(cited >= 6, "the lab ports are cited, found {cited}");
}

#[test]
fn catalog_images_and_ports_do_not_overlap() {
    check_disjoint(&entries()).unwrap();
}

#[test]
fn catalog_calls_are_read_only() {
    // validate() refuses a call outside READ_ONLY_CALLS; this also pins that every
    // listed call is used, so the list holds nothing that no entry needs.
    let mut used: BTreeSet<(String, String)> = BTreeSet::new();
    for (id, e) in entries() {
        let v = e["version"].as_table().unwrap();
        let form = call_form(v["source"].as_str().unwrap());
        used.insert((
            form.into(),
            descriptor(v["call"].as_table().unwrap(), form).unwrap(),
        ));
        for p in tables(e["recognize"].as_table().unwrap(), "probes", &id).unwrap() {
            let form = call_form(p["kind"].as_str().unwrap());
            used.insert((form.into(), descriptor(p, form).unwrap()));
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
    // validate() checks every URL; this pins what the real entries hold: repos in
    // owner/repo form, a website that is not just a code host, and every feed,
    // policy and key URL under the repo, a related repo, the website or a reviewed prefix.
    for (id, e) in entries() {
        let up = e["upstream"].as_table().unwrap();
        check_repo_url(up["repo"].as_str().unwrap()).unwrap();
        if let Some(w) = up.get("website").and_then(Value::as_str) {
            check_website(up["repo"].as_str().unwrap(), w).unwrap();
        }
        for f in ["security_policy", "release_feed"] {
            if let Some(u) = up.get(f).and_then(Value::as_str) {
                check_under_upstream(&id, up, f, u).unwrap_or_else(|e| panic!("{id}: {e}"));
            }
        }
        if let Some(u) = e["signing"].get("keys_url").and_then(Value::as_str) {
            check_under_upstream(&id, up, "keys_url", u).unwrap_or_else(|e| panic!("{id}: {e}"));
        }
        for f in e["advisories"]["feeds"].as_array().unwrap() {
            let u = f["url"].as_str().unwrap();
            check_under_upstream(&id, up, "advisories.feeds.url", u)
                .unwrap_or_else(|e| panic!("{id}: {e}"));
        }
    }
}

#[test]
fn catalog_holds_no_secret_shapes() {
    // Already part of validate; run the scan on the raw files again so a
    // failure names this test, and prove the scan lets the allowed shapes by.
    for (stem, text) in entry_files() {
        let t: Table = toml::from_str(&text).unwrap();
        no_secret_shapes(&t).unwrap_or_else(|e| panic!("{stem}: {e}"));
    }
    let ok: Table = toml::from_str(
        "a = \"documentation address 192.0.2.7, 2001:db8::1 and 2001:db8:abcd::5; TLS 1.3 at 12:30:45\"\n[signing]\nkeys = [{ fingerprint = \"0123456789abcdef0123456789abcdef01234567\" }]",
    )
    .unwrap();
    no_secret_shapes(&ok).unwrap();
}

#[test]
fn probe_patterns_are_bounded() {
    let mut probes = 0;
    for (id, e) in entries() {
        for p in tables(e["recognize"].as_table().unwrap(), "probes", &id).unwrap() {
            if let Some(m) = p.get("match").and_then(Value::as_str) {
                untrusted_regex(m).unwrap();
                probes += 1;
            }
        }
    }
    assert!(probes >= 2, "strfry and nutshell have probes with patterns");
    // A pattern too big for the limit, too long, with inline flags, or ending in an escaped $ is refused.
    assert!(untrusted_regex(r"^(?:[a-z]{1,1000}){1,1000}$").is_err());
    assert!(untrusted_regex(&format!("^{}$", "a".repeat(300))).is_err());
    assert!(untrusted_regex(r"^(?m)(?P<version>\d+)$").is_err());
    assert!(untrusted_regex(r"^(?s:.)$").is_err());
    assert!(untrusted_regex(r"^a\$").is_err());
    assert!(untrusted_regex(r"^a\\$").is_ok());
    // An alternation cannot match part of a reply: the pattern is wrapped in \A(?:...)\z.
    let alt = untrusted_regex(r"^nomatch|(?P<version>\d+\.\d+)\.0/$").unwrap();
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
            untrusted_regex(bad).unwrap_err().contains("on its own"),
            "{bad}"
        );
    }
    c(
        regex,
        r"regex = '^x)|(?:(?P<version>.*)$'",
        "compile on its own",
    );
    // the reply cap: a long reply is never matched
    let re = untrusted_regex(r"^(?P<version>\d+)$").unwrap();
    assert_eq!(extract(&re, "7").as_deref(), Some("7"));
    assert_eq!(extract(&re, &"7".repeat(MAX_RAW + 1)), None);

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
    check_disjoint(&good).unwrap();
    check_products(&good, &products, &UNCATALOGUED, &NOT_YET_IN_JUDGE_B).unwrap();
    check_unique(&good).unwrap();
    check_links(&good).unwrap();

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

    // Images and ports shared between entries, other than the listed one.
    let mut image = good.clone();
    image
        .get_mut("strfry")
        .unwrap()
        .get_mut("recognize")
        .unwrap()
        .as_table_mut()
        .unwrap()
        .insert(
            "images".into(),
            Value::Array(vec![Value::String("docker.io/lightninglabs/lnd".into())]),
        );
    assert!(check_disjoint(&image).unwrap_err().contains("overlap"));
    let mut wild = good.clone();
    wild.get_mut("strfry")
        .unwrap()
        .get_mut("recognize")
        .unwrap()
        .as_table_mut()
        .unwrap()
        .insert(
            "images".into(),
            Value::Array(vec![Value::String("docker.io/lightninglabs/*".into())]),
        );
    assert!(check_disjoint(&wild).unwrap_err().contains("overlap"));
    let mut shared = good.clone();
    shared
        .get_mut("strfry")
        .unwrap()
        .get_mut("recognize")
        .unwrap()
        .as_table_mut()
        .unwrap()
        .insert(
            "ports".into(),
            Value::Array(vec![Value::Table(
                toml::from_str("port = 10009\nproto = \"tcp\"\nwhat = \"x\"\nexposure = \"lan\"")
                    .unwrap(),
            )]),
        );
    assert!(
        check_disjoint(&shared)
            .unwrap_err()
            .contains("SHARED_PORTS")
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

    // A name used twice.
    let mut dup = good.clone();
    dup.get_mut("lnd").unwrap().insert(
        "aliases".into(),
        Value::Array(vec![Value::String("strfry".into())]),
    );
    assert!(check_unique(&dup).unwrap_err().contains("used by both"));

    // fork_of and bundles: a missing target, a self-reference, a cycle.
    let set = |m: &mut BTreeMap<String, Table>, id: &str, k: &str, v: Value| {
        m.get_mut(id).unwrap().insert(k.into(), v);
    };
    let mut fork = good.clone();
    set(&mut fork, "lnd", "fork_of", Value::String("nope".into()));
    assert!(check_links(&fork).unwrap_err().contains("not an entry"));
    let mut selfie = good.clone();
    set(
        &mut selfie,
        "lnd",
        "bundles",
        Value::Array(vec![Value::String("lnd".into())]),
    );
    assert!(check_links(&selfie).unwrap_err().contains("itself"));
    let mut cycle = good.clone();
    set(
        &mut cycle,
        "lnd",
        "bundles",
        Value::Array(vec![Value::String("strfry".into())]),
    );
    set(&mut cycle, "strfry", "fork_of", Value::String("lnd".into()));
    assert!(check_links(&cycle).unwrap_err().contains("cycle"));
}
