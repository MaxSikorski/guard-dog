//! The service catalog loader: `catalog/<id>.toml` as typed, validated data.
//!
//! The format is documented in `catalog/README.md`. [`load`] reads one entry
//! and performs every check that needs only the entry's own text. [`load_all`]
//! adds the checks that span entries (no shared image, the reviewed shared
//! ports, no name used twice, `fork_of` and `bundles` that resolve and never
//! cycle). [`embedded`] loads the entries compiled into the binary
//! (`catalog_files.rs`). Nothing here reads a file or the network: checks that
//! need a file in the repo (an example's `source`, an advisory's contents) or
//! another fixture (the lab's recorded replies, Judge B) stay in
//! `tests/catalog.rs`.
//!
//! The schema is closed: an unknown key anywhere is an error, and so is a
//! missing one. A catalog entry is data about a product, never instructions:
//! every regex that runs on a service's reply is anchored, bounded in size and
//! only ever run on replies of at most [`MAX_REPLY`] bytes.

use std::collections::{BTreeMap, BTreeSet};
use std::fmt;
use std::net::Ipv6Addr;
use std::sync::LazyLock;

use regex::{Regex, RegexBuilder};
use toml::{Table, Value};

use crate::catalog_files::FILES;

// ---------- reviewed lists ----------

/// Every call a catalog entry may make, exactly, as (form, descriptor): for
/// `cli` the argv joined by spaces, for `http` the method and path, for `rpc`
/// and `grpc` the method name. Anything else is refused, so adding a call is a
/// reviewed edit here. All of these only read. Every pair listed must be used
/// (pinned by a test).
pub const READ_ONLY_CALLS: [(&str, &str); 6] = [
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
pub const SHARED_PORTS: [(u16, &str, &str); 1] = [(
    9735,
    "tcp",
    "the Lightning peer-to-peer port is the same default for every Lightning node",
)];

/// Entries whose version regex may read plain versions of many majors, as (id, reason).
/// Exact: an entry listed here whose regex no longer needs it is refused.
pub const PLAIN_VERSION_OK: [(&str, &str); 1] = [(
    "strfry",
    "tagged builds report a plain x.y.z in NIP-11; the relay is recognised by the NIP-11 software probe, not by the version regex",
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

/// Most entries that may list the same port in `recognize.ports`. It must equal
/// the fact model's `MAX_CANDIDATES` (how many products one endpoint may be
/// matched against), so the catalog can never hand the scanner more candidates
/// than a fact can hold. [`load_all`] refuses a catalog over it.
pub const CATALOG_MAX_PRODUCTS_PER_PORT: usize = 32;

/// Size limit for any regex that runs on untrusted text.
const REGEX_SIZE_LIMIT: usize = 100_000;
/// Longest pattern.
const MAX_PATTERN: usize = 200;
/// Longest reply a catalog pattern is ever run on. Longer replies never match.
pub const MAX_REPLY: usize = 256;

// ---------- errors ----------

/// Why an entry, or the catalog as a whole, was refused.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CatalogError {
    entry: Option<String>,
    message: String,
}

impl CatalogError {
    fn entry(name: &str, message: String) -> Self {
        Self {
            entry: Some(name.to_string()),
            message,
        }
    }

    fn whole(message: String) -> Self {
        Self {
            entry: None,
            message,
        }
    }

    /// The reason, without the entry's name.
    #[must_use]
    pub fn message(&self) -> &str {
        &self.message
    }
}

impl fmt::Display for CatalogError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.entry {
            Some(e) => write!(f, "{e}: {}", self.message),
            None => f.write_str(&self.message),
        }
    }
}

impl std::error::Error for CatalogError {}

type R<T> = Result<T, String>;

// ---------- typed entry ----------

macro_rules! str_enum {
    ($(#[$m:meta])* $name:ident { $($(#[$vm:meta])* $v:ident = $s:literal),+ $(,)? }) => {
        $(#[$m])*
        #[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
        pub enum $name {
            $($(#[$vm])* $v),+
        }

        impl $name {
            const ALL: &'static [&'static str] = &[$($s),+];

            /// The name as written in a catalog entry.
            #[must_use]
            pub fn as_str(self) -> &'static str {
                match self {
                    $(Self::$v => $s),+
                }
            }

            fn from_key(t: &Table, k: &str, ctx: &str) -> R<Self> {
                match string(t, k, ctx)? {
                    $($s => Ok(Self::$v),)+
                    _ => Err(format!("{ctx}.{k} must be one of {:?}", Self::ALL)),
                }
            }
        }
    };
}

str_enum! {
    /// Where a product's version is read from.
    Source {
        /// A JSON-RPC method.
        Rpc = "rpc",
        /// A gRPC method.
        Grpc = "grpc",
        /// An HTTP GET.
        Http = "http",
        /// A Nostr NIP-11 relay information document (an HTTP GET).
        Nip11 = "nip11",
        /// A command line run as the service user.
        Cli = "cli",
        /// A container image label.
        ImageLabel = "image-label",
        /// A platform's app manifest.
        PlatformManifest = "platform-manifest",
    }
}

str_enum! {
    /// How a product's versions are ordered and compared.
    Scheme {
        /// Semantic versioning.
        Semver = "semver",
        /// `x.y.z-beta` and `-beta.rcN`.
        SemverBeta = "semver-beta",
        /// `0.x.y` before 22, `major.minor` from 22.
        BitcoinCore = "bitcoin-core",
        /// `major.minor`.
        MajorMinor = "major-minor",
        /// `git describe` output.
        GitDescribe = "git-describe",
        /// Calendar versions.
        Calver = "calver",
        /// No order is known.
        Opaque = "opaque",
    }
}

str_enum! {
    /// What kind of probe a `recognize.probes` item is.
    ProbeKind {
        /// A NIP-11 information document.
        Nip11 = "nip11",
        /// An HTTP GET.
        Http = "http",
        /// A JSON-RPC method.
        Rpc = "rpc",
        /// A gRPC method.
        Grpc = "grpc",
    }
}

str_enum! {
    /// A port's transport protocol.
    Proto {
        /// TCP.
        Tcp = "tcp",
        /// UDP.
        Udp = "udp",
    }
}

str_enum! {
    /// How far a port may be reachable.
    Exposure {
        /// Never from the internet.
        NeverPublic = "never-public",
        /// The local network.
        Lan = "lan",
        /// Public by design.
        PublicOk = "public-ok",
    }
}

str_enum! {
    /// Who runs a command-line call. Never root.
    RunAs {
        /// The service user inside the container.
        ServiceUserInContainer = "service-user-in-container",
        /// The service user on the host.
        ServiceUserOnHost = "service-user-on-host",
    }
}

str_enum! {
    /// Where a gRPC server's certificate comes from.
    CertSource {
        /// The certificate the node generated.
        NodeTlsCert = "node-tls-cert",
        /// The system's root certificates.
        SystemRoots = "system-roots",
        /// A certificate pinned in Guard Dog's config.
        PinnedInConfig = "pinned-in-config",
    }
}

/// A structured, read-only call. Never a shell string.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Call {
    /// A command line: a bare program from `recognize.binaries` and plain words.
    Cli {
        /// The program, then its arguments.
        argv: Vec<String>,
        /// Who runs it.
        run_as: RunAs,
    },
    /// An HTTP GET of a local path on the matched service's own endpoint.
    Http {
        /// The path, like `/v1/info`.
        path: String,
        /// The `Accept` media type, if one is needed.
        accept: Option<String>,
    },
    /// A JSON-RPC method.
    Rpc {
        /// The method name.
        method: String,
    },
    /// A gRPC method, with its package, like `verrpc.Versioner/GetVersion`.
    Grpc {
        /// The method name.
        method: String,
    },
}

impl Call {
    /// The call as [`READ_ONLY_CALLS`] spells it: (form, descriptor).
    #[must_use]
    pub fn descriptor(&self) -> (&'static str, String) {
        match self {
            Self::Cli { argv, .. } => ("cli", argv.join(" ")),
            Self::Http { path, .. } => ("http", format!("GET {path}")),
            Self::Rpc { method } => ("rpc", method.clone()),
            Self::Grpc { method } => ("grpc", method.clone()),
        }
    }
}

/// A regex that runs on a service's reply. Anchored as `\A(?:pattern)\z`, at
/// most 200 characters, no inline flags, a size limit on the compiled program,
/// and only ever run on replies of at most [`MAX_REPLY`] bytes.
#[derive(Clone, Debug)]
pub struct Pattern {
    re: Regex,
}

impl Pattern {
    /// Compiles a pattern that starts with `^` and ends with an unescaped `$`.
    ///
    /// # Errors
    /// The reason, when the pattern is unanchored, too long, uses inline flags
    /// or does not compile within the size limit.
    pub fn new(pattern: &str) -> Result<Self, String> {
        untrusted_regex(pattern).map(|re| Self { re })
    }

    /// Like [`Pattern::new`], and the pattern needs a group named `version`.
    ///
    /// # Errors
    /// The reason, as for [`Pattern::new`], or a missing `version` group.
    pub fn new_version(pattern: &str) -> Result<Self, String> {
        let p = Self::new(pattern).map_err(|e| format!("version.regex: {e}"))?;
        if !p.re.capture_names().flatten().any(|n| n == "version") {
            return Err("version.regex needs a group named `version`".into());
        }
        Ok(p)
    }

    /// Does the whole reply match? A reply over [`MAX_REPLY`] bytes never does.
    #[must_use]
    pub fn matches(&self, reply: &str) -> bool {
        reply.len() <= MAX_REPLY && self.re.is_match(reply)
    }

    /// The `version` group of a whole-reply match. A reply over [`MAX_REPLY`]
    /// bytes, or one the pattern only partly matches, gives `None`.
    #[must_use]
    pub fn version<'a>(&self, reply: &'a str) -> Option<&'a str> {
        if reply.len() > MAX_REPLY {
            return None;
        }
        self.re.captures(reply)?.name("version").map(|m| m.as_str())
    }
}

/// `[upstream]`: where the project lives.
#[derive(Clone, Debug)]
pub struct Upstream {
    /// `https://host/owner/repo`.
    pub repo: String,
    /// The project's website.
    pub website: Option<String>,
    /// Its security policy.
    pub security_policy: Option<String>,
    /// Its release feed.
    pub release_feed: Option<String>,
    /// Other repos on the same code host (for example a signature repo).
    pub related_repos: Vec<String>,
}

/// One `[[recognize.ports]]` item.
#[derive(Clone, Debug)]
pub struct Port {
    /// 1 to 65535.
    pub port: u16,
    /// Transport protocol.
    pub proto: Proto,
    /// What the port is for.
    pub what: String,
    /// How far it may be reachable.
    pub exposure: Exposure,
    /// A repo file or upstream URL that says so.
    pub source: Option<String>,
}

/// One `[[recognize.probes]]` item: a read-only call that helps tell a product apart.
#[derive(Clone, Debug)]
pub struct Probe {
    /// The kind of call.
    pub kind: ProbeKind,
    /// The call.
    pub call: Call,
    /// The port it goes to (default: `version.endpoint_port`).
    pub port: Option<u16>,
    /// The reply field the pattern reads, when there is a pattern.
    pub field: Option<String>,
    matcher: Option<Pattern>,
}

impl Probe {
    /// The anchored pattern this probe's field must match, if it has one.
    #[must_use]
    pub fn pattern(&self) -> Option<&Pattern> {
        self.matcher.as_ref()
    }

    /// Does the probe's pattern match this reply field? `false` with no pattern,
    /// and for a reply over [`MAX_REPLY`] bytes.
    #[must_use]
    pub fn matches(&self, reply: &str) -> bool {
        self.matcher.as_ref().is_some_and(|p| p.matches(reply))
    }
}

/// `[recognize]`: how to tell the product is there.
#[derive(Clone, Debug)]
pub struct Recognize {
    /// Normalised image names (`docker.io/namespace/repo`, `*` only at the end).
    pub images: Vec<String>,
    /// Program names.
    pub binaries: Vec<String>,
    /// systemd unit names.
    pub units: Vec<String>,
    /// Ports the product listens on.
    pub ports: Vec<Port>,
    /// Probes.
    pub probes: Vec<Probe>,
}

/// `[version.tls]` of a gRPC source. There is no way to skip verification.
#[derive(Clone, Debug)]
pub struct Tls {
    /// Where the certificate comes from.
    pub cert_source: CertSource,
    /// `localhost` or the entry's own id.
    pub server_name: String,
}

/// `[version.call]`.
#[derive(Clone, Debug)]
pub struct VersionCall {
    /// The reply field read: a plain dotted name.
    pub field: String,
    /// The call; `None` for `image-label` and `platform-manifest` sources.
    pub call: Option<Call>,
}

/// One `[[version.examples]]` item.
#[derive(Clone, Debug)]
pub struct Example {
    /// The reply, as sent.
    pub raw: String,
    /// The version the regex must read from it.
    pub version: String,
    /// A repo file or upstream URL.
    pub source: String,
    /// True for an example that comes from an advisory, not a real reply.
    pub advisory: bool,
}

/// `[version]`: how to read the product's version.
#[derive(Clone, Debug)]
pub struct Version {
    /// Where the version is read from.
    pub source: Source,
    /// The least-privileged credential, in words.
    pub credential: String,
    /// The regex source text.
    pub regex: String,
    /// How versions compare.
    pub scheme: Scheme,
    /// The port a network source goes to, one of `recognize.ports`.
    pub endpoint_port: Option<u16>,
    /// TLS, for a gRPC source.
    pub tls: Option<Tls>,
    /// The call and the field read from its reply.
    pub call: VersionCall,
    /// Replies and the versions they give.
    pub examples: Vec<Example>,
    pattern: Pattern,
}

/// One `[[platform_map]]` item.
#[derive(Clone, Debug)]
pub struct PlatformMap {
    /// The platform.
    pub platform: String,
    /// The app id the platform uses.
    pub app_id: String,
    /// How the platform's version relates to the product's.
    pub version_rule: String,
    /// A note.
    pub note: Option<String>,
}

/// One `[[advisories.feeds]]` item.
#[derive(Clone, Debug)]
pub struct Feed {
    /// `atom`, `rss`, `markdown-repo` or `release-notes`.
    pub kind: String,
    /// An https URL under the upstream.
    pub url: String,
}

/// `[advisories]`: where the product's security advisories come from.
#[derive(Clone, Debug)]
pub struct Advisories {
    /// `"<ECOSYSTEM> <name>"`.
    pub osv_packages: Vec<String>,
    /// Does the project publish GitHub security advisories?
    pub ghsa: bool,
    /// Machine-readable feeds.
    pub feeds: Vec<Feed>,
    /// In words, when the project's advisories are known to be incomplete.
    pub blind_spot: Option<String>,
}

/// One `[[signing.keys]]` item.
#[derive(Clone, Debug)]
pub struct SigningKey {
    /// Whose key.
    pub who: String,
    /// 40 hex characters.
    pub fingerprint: String,
    /// The date the fingerprint was checked.
    pub checked: String,
}

/// `[signing]`: how the product's releases are signed.
#[derive(Clone, Debug)]
pub struct Signing {
    /// `signed-multi`, `signed-single`, `tag-only`, `unsigned` or `unknown`.
    pub level: String,
    /// How, in words.
    pub method: Option<String>,
    /// Where the keys are published.
    pub keys_url: Option<String>,
    /// For `signed-multi`, how many signatures make a release trustworthy.
    pub min_signatures: Option<u32>,
    /// `yes`, `no` or `unverified`.
    pub reproducible: Option<String>,
    /// Are the container images signed?
    pub images_signed: Option<bool>,
    /// Known key fingerprints.
    pub keys: Vec<SigningKey>,
}

/// `[review]`: what was checked and what is still open.
#[derive(Clone, Debug)]
pub struct Review {
    /// A date, `YYYY-MM-DD`.
    pub last_reviewed: String,
    /// https pages the facts come from.
    pub sources: Vec<String>,
    /// Open questions, never guessed values.
    pub todo: Vec<String>,
}

/// One catalog entry, validated.
#[derive(Clone, Debug)]
pub struct Entry {
    /// The slug; equals the file name.
    pub id: String,
    /// The display name.
    pub name: String,
    /// `service`, `platform`, `device`, `app`, `miner` or `package`.
    pub kind: String,
    /// Other names advisories use.
    pub aliases: Vec<String>,
    /// One plain-English line.
    pub summary: String,
    /// Does it hold funds or keys, or host software that does?
    pub money: bool,
    /// The upstream licence.
    pub licence: String,
    /// The entry this one is a fork of.
    pub fork_of: Option<String>,
    /// Entries this product ships; one fact per bundled id.
    pub bundles: Vec<String>,
    /// Where the project lives.
    pub upstream: Upstream,
    /// How to recognise it.
    pub recognize: Recognize,
    /// How to read its version.
    pub version: Version,
    /// How platforms package it.
    pub platform_map: Vec<PlatformMap>,
    /// Where its advisories come from.
    pub advisories: Advisories,
    /// How its releases are signed.
    pub signing: Signing,
    /// What was checked.
    pub review: Review,
}

impl Entry {
    /// The display name.
    #[must_use]
    pub fn display_name(&self) -> &str {
        &self.name
    }

    /// How versions of this product compare.
    #[must_use]
    pub fn scheme(&self) -> Scheme {
        self.version.scheme
    }

    /// The OSV packages (`"<ECOSYSTEM> <name>"`) whose advisories apply.
    #[must_use]
    pub fn osv_packages(&self) -> &[String] {
        &self.advisories.osv_packages
    }

    /// The version call: source, call (method, path, accept or argv), field read,
    /// endpoint port and TLS.
    #[must_use]
    pub fn version_call(&self) -> &Version {
        &self.version
    }

    /// Reads the version from a reply. The whole reply must match the entry's
    /// anchored regex, and a reply over [`MAX_REPLY`] bytes is never matched.
    #[must_use]
    pub fn match_version<'a>(&self, reply: &'a str) -> Option<&'a str> {
        self.version.pattern.version(reply)
    }

    /// Every call this entry makes, as (form, descriptor), for comparing with
    /// [`READ_ONLY_CALLS`]: the version call, then each probe.
    #[must_use]
    pub fn call_descriptors(&self) -> Vec<(&'static str, String)> {
        let mut out: Vec<(&'static str, String)> = Vec::new();
        out.extend(self.version.call.call.iter().map(Call::descriptor));
        out.extend(self.recognize.probes.iter().map(|p| p.call.descriptor()));
        out
    }
}

/// All entries, validated together.
#[derive(Clone, Debug)]
pub struct Catalog {
    entries: BTreeMap<String, Entry>,
}

impl Catalog {
    /// The entry with this id.
    #[must_use]
    pub fn get(&self, id: &str) -> Option<&Entry> {
        self.entries.get(id)
    }

    /// Every entry, sorted by id.
    pub fn entries(&self) -> impl Iterator<Item = &Entry> {
        self.entries.values()
    }

    /// How many entries.
    #[must_use]
    pub fn len(&self) -> usize {
        self.entries.len()
    }

    /// Is the catalog empty?
    #[must_use]
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }

    /// The entries whose `recognize.ports` include this port, sorted by id.
    #[must_use]
    pub fn entries_on_port(&self, port: u16) -> Vec<&Entry> {
        self.entries
            .values()
            .filter(|e| e.recognize.ports.iter().any(|p| p.port == port))
            .collect()
    }
}

// ---------- loading ----------

/// Loads and validates one entry. `name` is the file name without `.toml`, and
/// it must equal the entry's `id`. Every per-entry rule runs here.
///
/// # Errors
/// The first rule the entry breaks, with the entry's name.
pub fn load(name: &str, text: &str) -> Result<Entry, CatalogError> {
    let t: Table = toml::from_str(text)
        .map_err(|e| CatalogError::entry(name, format!("not valid TOML: {e}")))?;
    let entry = parse_entry(&t, name).map_err(|e| CatalogError::entry(name, e))?;
    no_secret_shapes(&t).map_err(|e| CatalogError::entry(name, e))?;
    Ok(entry)
}

/// Loads every entry, then runs the checks that span entries.
///
/// # Errors
/// The first entry that fails [`load`], a name used twice, an image two
/// entries share, a port shared outside [`SHARED_PORTS`], or a `fork_of` or
/// `bundles` that names a missing entry, itself, or forms a cycle.
pub fn load_all(files: &[(&str, &str)]) -> Result<Catalog, CatalogError> {
    let mut entries: BTreeMap<String, Entry> = BTreeMap::new();
    for (name, text) in files {
        let entry = load(name, text)?;
        if entries.insert((*name).to_string(), entry).is_some() {
            return Err(CatalogError::entry(name, "the file is listed twice".into()));
        }
    }
    check_unique(&entries).map_err(CatalogError::whole)?;
    check_disjoint(&entries).map_err(CatalogError::whole)?;
    check_links(&entries).map_err(CatalogError::whole)?;
    Ok(Catalog { entries })
}

/// The catalog compiled into this binary (`catalog_files.rs`).
///
/// # Errors
/// As [`load_all`]. The shipped entries are tested to load, so an error means
/// the build is broken.
pub fn embedded() -> Result<Catalog, CatalogError> {
    load_all(FILES)
}

// ---------- reading helpers ----------

fn check_keys(t: &Table, ctx: &str, required: &[&str], optional: &[&str]) -> R<()> {
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

fn string<'a>(t: &'a Table, k: &str, ctx: &str) -> R<&'a str> {
    match t.get(k) {
        Some(Value::String(s)) => Ok(s),
        _ => Err(format!("{ctx}.{k} must be a string")),
    }
}

fn line<'a>(t: &'a Table, k: &str, ctx: &str) -> R<&'a str> {
    let s = string(t, k, ctx)?;
    if s.is_empty() || s.chars().any(char::is_control) {
        return Err(format!("{ctx}.{k} must be one non-empty line"));
    }
    Ok(s)
}

fn one_of<'a>(t: &'a Table, k: &str, ctx: &str, allowed: &[&str]) -> R<&'a str> {
    let s = string(t, k, ctx)?;
    if allowed.contains(&s) {
        Ok(s)
    } else {
        Err(format!("{ctx}.{k} must be one of {allowed:?}"))
    }
}

fn boolean(t: &Table, k: &str, ctx: &str) -> R<bool> {
    match t.get(k) {
        Some(Value::Boolean(b)) => Ok(*b),
        _ => Err(format!("{ctx}.{k} must be true or false")),
    }
}

fn table<'a>(t: &'a Table, k: &str, ctx: &str) -> R<&'a Table> {
    match t.get(k) {
        Some(Value::Table(x)) => Ok(x),
        _ => Err(format!("{ctx}.{k} must be a table")),
    }
}

fn tables<'a>(t: &'a Table, k: &str, ctx: &str) -> R<Vec<&'a Table>> {
    match t.get(k) {
        None => Ok(Vec::new()),
        Some(Value::Array(a)) => a
            .iter()
            .map(|v| v.as_table().ok_or(format!("{ctx}.{k} must hold tables")))
            .collect(),
        _ => Err(format!("{ctx}.{k} must be a list of tables")),
    }
}

fn strings(t: &Table, k: &str, ctx: &str) -> R<Vec<String>> {
    match t.get(k) {
        Some(Value::Array(a)) => a
            .iter()
            .map(|v| {
                v.as_str()
                    .map(str::to_string)
                    .ok_or(format!("{ctx}.{k} must hold strings"))
            })
            .collect(),
        _ => Err(format!("{ctx}.{k} must be a list of strings")),
    }
}

fn strings_opt(t: &Table, k: &str, ctx: &str) -> R<Vec<String>> {
    if t.contains_key(k) {
        strings(t, k, ctx)
    } else {
        Ok(Vec::new())
    }
}

fn opt_line(t: &Table, k: &str, ctx: &str) -> R<Option<String>> {
    if t.contains_key(k) {
        Ok(Some(line(t, k, ctx)?.to_string()))
    } else {
        Ok(None)
    }
}

fn is_slug(s: &str) -> bool {
    s.len() <= 40
        && s.split('-').all(|p| {
            !p.is_empty()
                && p.chars()
                    .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit())
        })
}

fn is_date(v: &Value) -> bool {
    matches!(v, Value::Datetime(d) if d.date.is_some() && d.time.is_none() && d.offset.is_none())
}

fn date_string(t: &Table, k: &str, what: &str) -> R<String> {
    match t.get(k) {
        Some(v @ Value::Datetime(d)) if is_date(v) => Ok(d.to_string()),
        _ => Err(format!("{what} must be a date")),
    }
}

fn port_number(n: i64) -> Option<u16> {
    u16::try_from(n).ok().filter(|p| *p >= 1)
}

// ---------- fixed regexes ----------

/// Regexes the loader itself uses, compiled once. A failure to compile one is
/// reported as an error, never a panic.
struct Fixed {
    inline_flags: Regex,
    host_like: Regex,
    forty_hex: Regex,
    shapes: Vec<(&'static str, Regex)>,
}

static FIXED: LazyLock<Result<Fixed, String>> = LazyLock::new(|| {
    build_fixed().map_err(|e| format!("internal error: a built-in pattern does not compile: {e}"))
});

fn fixed() -> R<&'static Fixed> {
    FIXED.as_ref().map_err(Clone::clone)
}

fn build_fixed() -> Result<Fixed, regex::Error> {
    let shapes: [(&'static str, &str); 14] = [
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
    let mut compiled = Vec::new();
    for (name, pattern) in shapes {
        compiled.push((name, Regex::new(pattern)?));
    }
    Ok(Fixed {
        inline_flags: Regex::new(r"\(\?[a-zA-Z-]+[:)]")?,
        host_like: Regex::new(r"(?i)\b[a-z0-9][a-z0-9-]*(?:\.[a-z0-9-]+)+\b")?,
        forty_hex: Regex::new(r"\b[0-9a-fA-F]{40}\b")?,
        shapes: compiled,
    })
}

/// A catalog regex that runs on untrusted text. It must start with `^` and end
/// with an unescaped `$`, be at most 200 characters, and carry no inline flags
/// (`(?m)`, `(?s)`, `(?x)` and so on). It is compiled as `\A(?:pattern)\z`, so
/// an alternation inside it can never match part of a reply, and with a size limit.
fn untrusted_regex(pattern: &str) -> R<Regex> {
    if pattern.len() < 2 || !pattern.starts_with('^') || !pattern.ends_with('$') {
        return Err(format!("pattern must be anchored (^...$): {pattern}"));
    }
    let slashes = pattern
        .strip_suffix('$')
        .unwrap_or(pattern)
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
    if fixed()?.inline_flags.is_match(pattern) {
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
fn https_parts(url: &str) -> R<(&str, &str)> {
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
fn check_repo_url(url: &str) -> R<()> {
    let (_, path) = https_parts(url)?;
    let segs: Vec<&str> = path.trim_matches('/').split('/').collect();
    if segs.len() != 2 || segs.iter().any(|s| s.is_empty()) || path.ends_with('/') {
        return Err(format!("repo URL must be https://host/owner/repo: {url}"));
    }
    Ok(())
}

/// A website may not sit on a shared code host unless it is exactly the repo.
fn check_website(repo: &str, site: &str) -> R<()> {
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
fn check_under_upstream(id: &str, up: &Upstream, field: &str, url: &str) -> R<()> {
    https_parts(url)?;
    let mut bases: Vec<&str> = vec![&up.repo];
    bases.extend(up.related_repos.iter().map(String::as_str));
    bases.extend(up.website.as_deref());
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

/// A `source` is a file in the repo, or an https URL under the entry's own
/// upstream. That the file exists is checked where the repo is on disk
/// (`tests/catalog.rs`); here only its form.
fn check_source(id: &str, up: &Upstream, field: &str, src: &str) -> R<()> {
    if src.starts_with("https://") {
        check_under_upstream(id, up, field, src)
    } else if src.contains("..") || src.starts_with('/') {
        Err(format!(
            "{field} must be a file in the repo or a URL under the upstream: {src}"
        ))
    } else {
        Ok(())
    }
}

/// An advisory example's `source`: a `.json` file under `advisories/corpus/`.
fn is_advisory_file(src: &str) -> bool {
    src.starts_with("advisories/corpus/")
        && std::path::Path::new(src)
            .extension()
            .is_some_and(|e| e.eq_ignore_ascii_case("json"))
        && !src.contains("..")
}

// ---------- calls, probes and credentials ----------

/// Text in a call, probe or credential never names a place: no scheme, host,
/// user info, `..`, link-local or metadata address, or onion address. Method
/// names may contain dots (`verrpc.Versioner/GetVersion`), so they skip the
/// host-name test and are held to the exact READ_ONLY_CALLS list instead.
fn no_endpoint_text(label: &str, s: &str, host_test: bool) -> R<()> {
    let lower = s.to_ascii_lowercase();
    let bad = lower.contains("://")
        || s.contains('@')
        || s.contains("..")
        || lower.contains(".onion")
        || lower.contains("169.254.")
        || lower.contains("fe80:")
        || lower.contains("metadata")
        || (host_test && fixed()?.host_like.is_match(s));
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

fn all_chars(s: &str, ok: impl Fn(char) -> bool) -> bool {
    s.chars().all(ok)
}

/// Checks the structured call keys (`argv`, `run_as`, `method`, `path`, `accept`)
/// present in `t` for a call of this form, builds the call, and checks that it
/// is in READ_ONLY_CALLS. Never a shell string. `None` for a source with no call.
fn parse_call(t: &Table, form: &str, ctx: &str, binaries: &[String]) -> R<Option<Call>> {
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
    let call = match form {
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
            if NEVER_RUN.contains(&first.as_str()) {
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
            Some(Call::Cli {
                argv,
                run_as: RunAs::from_key(t, "run_as", ctx)?,
            })
        }
        "http" => {
            if string(t, "method", ctx)? != "GET" {
                return Err(format!("{ctx}.method must be GET (read-only)"));
            }
            let path = string(t, "path", ctx)?;
            let path_ok = path.starts_with('/')
                && all_chars(path, |c| {
                    c.is_ascii_alphanumeric() || matches!(c, '_' | '~' | '/' | '-')
                });
            if !path_ok || path.contains("//") {
                return Err(format!(
                    "{ctx}.path must be a local path like /v1/info: {path}"
                ));
            }
            let accept = if has("accept") {
                let a = string(t, "accept", ctx)?;
                let mime_ok = a.split_once('/').is_some_and(|(l, r)| {
                    !l.is_empty()
                        && all_chars(l, |c| c.is_ascii_lowercase())
                        && !r.is_empty()
                        && all_chars(r, |c| {
                            c.is_ascii_lowercase() || c.is_ascii_digit() || c == '+' || c == '-'
                        })
                });
                if !mime_ok {
                    return Err(format!("{ctx}.accept must be a media type"));
                }
                Some(a.to_string())
            } else {
                None
            };
            Some(Call::Http {
                path: path.to_string(),
                accept,
            })
        }
        "rpc" | "grpc" => {
            let m = string(t, "method", ctx)?;
            let name_ok = (1..=80).contains(&m.len())
                && all_chars(m, |c| {
                    c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '/')
                });
            if !name_ok {
                return Err(format!("{ctx}.method must be a method name: {m}"));
            }
            no_endpoint_text(&format!("{ctx}.method"), m, false)?;
            let method = m.to_string();
            Some(if form == "rpc" {
                Call::Rpc { method }
            } else {
                Call::Grpc { method }
            })
        }
        _ => None,
    };
    if let Some(c) = &call {
        let (f, d) = c.descriptor();
        if !READ_ONLY_CALLS.iter().any(|(rf, rd)| *rf == f && *rd == d) {
            return Err(format!(
                "{ctx}: the {f} call `{d}` is not in READ_ONLY_CALLS"
            ));
        }
    }
    Ok(call)
}

/// The reply field a call reads: a plain dotted name.
fn check_field(t: &Table, ctx: &str) -> R<String> {
    let f = line(t, "field", ctx)?;
    let ok = (1..=64).contains(&f.len())
        && all_chars(f, |c| c.is_ascii_alphanumeric() || c == '_' || c == '.');
    if !ok || f.contains("..") {
        return Err(format!(
            "{ctx}.field must match [A-Za-z0-9_.]{{1,64}} with no `..`: {f}"
        ));
    }
    Ok(f.to_string())
}

// ---------- secret shapes ----------

/// Is this token a real IPv6 address outside the documentation range 2001:db8::/32?
fn is_public_ipv6(token: &str) -> bool {
    if token.matches(':').count() < 2 {
        return false;
    }
    match token.parse::<Ipv6Addr>() {
        Ok(a) => {
            let s = a.segments();
            !(s.first() == Some(&0x2001) && s.get(1) == Some(&0x0db8))
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

fn no_secret_shapes(t: &Table) -> R<()> {
    let fx = fixed()?;
    let mut all = Vec::new();
    for (k, v) in t {
        collect_strings(&format!(".{k}"), v, &mut all);
    }
    for (path, s) in all {
        for (name, re) in &fx.shapes {
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
        if fx.forty_hex.is_match(&s) && !is_fingerprint_path(&path) {
            return Err(format!(
                "{path} has a secret shape: 40-hex outside signing.keys.fingerprint"
            ));
        }
    }
    Ok(())
}

/// Runs only the secret-shape scan on TOML text: no xpub or xprv, nsec,
/// 12-word seed phrase, 64-hex or longer string, base64 macaroon, onion
/// address, Lightning invoice, Cashu token, GitHub, AWS or `sk-` token,
/// private key block, public IPv4 or IPv6 address, or a 40-hex string outside
/// `signing.keys.fingerprint`. [`load`] already runs it.
///
/// # Errors
/// The first value with a secret shape, or text that is not TOML.
pub fn scan_secret_shapes(text: &str) -> Result<(), CatalogError> {
    let t: Table =
        toml::from_str(text).map_err(|e| CatalogError::whole(format!("not valid TOML: {e}")))?;
    no_secret_shapes(&t).map_err(CatalogError::whole)
}

// ---------- images ----------

/// The one image-name normaliser: lower case, no digest, no tag, `docker.io/`
/// when no registry is given, and `library/` for Docker Hub's single names. A
/// registry may carry a port (`localhost:5000/a/b`). A trailing `*` (a pattern) is kept.
#[must_use]
pub fn normalise_image(image: &str) -> String {
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
    let first = parts.first().copied().unwrap_or("");
    let has_registry = parts.len() > 1 && (first.contains('.') || first.contains(':'));
    if has_registry {
        if (first == "index.docker.io" || first == "registry-1.docker.io")
            && let Some(p) = parts.first_mut()
        {
            *p = "docker.io";
        }
    } else {
        parts.insert(0, "docker.io");
    }
    if parts.first() == Some(&"docker.io") && parts.len() == 2 {
        parts.insert(1, "library");
    }
    format!("{}{star}", parts.join("/"))
}

fn check_image_pattern(img: &str) -> R<()> {
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

/// Plain versions across many major numbers: `N.2.3` for N in 0 to 40, `100.0.0` and
/// `2026.1.0`. A regex that reads more than one major claims any product's reply,
/// whatever way it is spelled.
fn major_sweep() -> Vec<String> {
    let mut v: Vec<String> = (0..=40).map(|n| format!("{n}.2.3")).collect();
    v.push("100.0.0".into());
    v.push("2026.1.0".into());
    v
}

// ---------- one entry ----------

fn parse_entry(t: &Table, stem: &str) -> R<Entry> {
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
    let name = line(t, "name", "entry")?.to_string();
    let kind = one_of(t, "kind", "entry", &KINDS)?.to_string();
    let aliases = strings(t, "aliases", "entry")?;
    for a in &aliases {
        if !is_slug(a) {
            return Err(format!("alias `{a}` must be a slug"));
        }
    }
    let summary = line(t, "summary", "entry")?.to_string();
    let money = boolean(t, "money", "entry")?;
    let licence = line(t, "licence", "entry")?.to_string();
    let fork_of = if t.contains_key("fork_of") {
        let f = string(t, "fork_of", "entry")?;
        if !is_slug(f) {
            return Err("fork_of must be a slug".into());
        }
        Some(f.to_string())
    } else {
        None
    };
    let bundles = strings_opt(t, "bundles", "entry")?;
    for b in &bundles {
        if !is_slug(b) {
            return Err(format!("bundles entry `{b}` must be a slug"));
        }
    }

    // [review] is read first: open `todo` items excuse some gaps below.
    let rv = table(t, "review", "entry")?;
    check_keys(rv, "review", &["last_reviewed", "sources", "todo"], &[])?;
    let todo = strings(rv, "todo", "review")?;
    let has_todo = |prefix: &str| todo.iter().any(|i| i.starts_with(prefix));

    let upstream = parse_upstream(id, t)?;
    let recognize = parse_recognize(id, t, &upstream, &has_todo)?;
    let version = parse_version(id, t, &upstream, &recognize, &has_todo)?;

    let mut platform_map = Vec::new();
    for m in tables(t, "platform_map", "entry")? {
        check_keys(
            m,
            "platform_map",
            &["platform", "app_id", "version_rule"],
            &["note"],
        )?;
        platform_map.push(PlatformMap {
            platform: one_of(m, "platform", "platform_map", &PLATFORMS)?.to_string(),
            app_id: line(m, "app_id", "platform_map")?.to_string(),
            version_rule: one_of(m, "version_rule", "platform_map", &VERSION_RULES)?.to_string(),
            note: m.get("note").and_then(Value::as_str).map(str::to_string),
        });
    }

    let advisories = parse_advisories(id, t, &upstream)?;
    let signing = parse_signing(id, t, &upstream, &has_todo)?;

    // rest of [review]
    let last_reviewed = date_string(rv, "last_reviewed", "review.last_reviewed")?;
    let sources = strings(rv, "sources", "review")?;
    if sources.is_empty() {
        return Err("review.sources must cite at least one page".into());
    }
    for s in &sources {
        https_parts(s)?;
    }
    for item in &todo {
        if item.is_empty() || item.chars().any(char::is_control) {
            return Err("review.todo items must be one non-empty line".into());
        }
    }

    Ok(Entry {
        id: id.to_string(),
        name,
        kind,
        aliases,
        summary,
        money,
        licence,
        fork_of,
        bundles,
        upstream,
        recognize,
        version,
        platform_map,
        advisories,
        signing,
        review: Review {
            last_reviewed,
            sources,
            todo: todo.clone(),
        },
    })
}

fn parse_upstream(id: &str, t: &Table) -> R<Upstream> {
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
    let repo = string(up, "repo", "upstream")?.to_string();
    check_repo_url(&repo)?;
    let (repo_host, _) = https_parts(&repo)?;
    let related_repos = strings_opt(up, "related_repos", "upstream")?;
    for r in &related_repos {
        check_repo_url(r)?;
        if *r == repo {
            return Err("related_repos must not repeat upstream.repo".into());
        }
        if https_parts(r)?.0 != repo_host {
            return Err(format!(
                "related_repos must be on the same code host as the repo: {r}"
            ));
        }
    }
    let website = if up.contains_key("website") {
        let w = string(up, "website", "upstream")?;
        check_website(&repo, w)?;
        Some(w.to_string())
    } else {
        None
    };
    let mut out = Upstream {
        repo,
        website,
        security_policy: None,
        release_feed: None,
        related_repos,
    };
    for f in ["security_policy", "release_feed"] {
        if up.contains_key(f) {
            let u = string(up, f, "upstream")?;
            check_under_upstream(id, &out, f, u)?;
            if f == "security_policy" {
                out.security_policy = Some(u.to_string());
            } else {
                out.release_feed = Some(u.to_string());
            }
        }
    }
    Ok(out)
}

fn parse_recognize(
    id: &str,
    t: &Table,
    up: &Upstream,
    has_todo: &dyn Fn(&str) -> bool,
) -> R<Recognize> {
    let rec = table(t, "recognize", "entry")?;
    check_keys(
        rec,
        "recognize",
        &["images", "binaries", "units"],
        &["ports", "probes"],
    )?;
    let images = strings(rec, "images", "recognize")?;
    for img in &images {
        check_image_pattern(img)?;
    }
    let binaries = strings(rec, "binaries", "recognize")?;
    if binaries.is_empty() && !has_todo("binaries:") {
        return Err("recognize.binaries is empty and review.todo has no `binaries:` item".into());
    }
    let units = strings(rec, "units", "recognize")?;
    if units.is_empty() && !has_todo("units:") {
        return Err("recognize.units is empty and review.todo has no `units:` item".into());
    }
    let mut ports: Vec<Port> = Vec::new();
    for p in tables(rec, "ports", "recognize")? {
        check_keys(
            p,
            "recognize.ports",
            &["port", "proto", "what", "exposure"],
            &["source"],
        )?;
        let port = match p.get("port") {
            Some(Value::Integer(n)) => {
                port_number(*n).ok_or("recognize.ports.port must be 1 to 65535")?
            }
            _ => return Err("recognize.ports.port must be 1 to 65535".into()),
        };
        let proto = Proto::from_key(p, "proto", "recognize.ports")?;
        let what = line(p, "what", "recognize.ports")?.to_string();
        let exposure = Exposure::from_key(p, "exposure", "recognize.ports")?;
        let source = if p.contains_key("source") {
            let s = line(p, "source", "recognize.ports")?;
            check_source(id, up, "recognize.ports.source", s)?;
            Some(s.to_string())
        } else {
            None
        };
        ports.push(Port {
            port,
            proto,
            what,
            exposure,
            source,
        });
    }
    let version_port = t
        .get("version")
        .and_then(Value::as_table)
        .is_some_and(|v| v.contains_key("endpoint_port"));
    let mut probes = Vec::new();
    for p in tables(rec, "probes", "recognize")? {
        check_keys(
            p,
            "recognize.probes",
            &["kind", "method"],
            &["path", "accept", "port", "field", "match"],
        )?;
        let kind = ProbeKind::from_key(p, "kind", "recognize.probes")?;
        let call = parse_call(p, call_form(kind.as_str()), "recognize.probes", &binaries)?
            .ok_or("recognize.probes: a probe is a call")?;
        let port = match p.get("port") {
            Some(Value::Integer(n))
                if port_number(*n).is_some_and(|x| ports.iter().any(|q| q.port == x)) =>
            {
                port_number(*n)
            }
            Some(_) => return Err("recognize.probes.port must be one of recognize.ports".into()),
            None if version_port || has_todo("ports:") => None,
            None => {
                return Err(
                    "recognize.probes needs a port (or version.endpoint_port, or a `ports:` todo)"
                        .into(),
                );
            }
        };
        if p.contains_key("field") != p.contains_key("match") {
            return Err("recognize.probes: field and match go together".into());
        }
        let (field, matcher) = if p.contains_key("match") {
            let f = check_field(p, "recognize.probes")?;
            let m = Pattern::new(string(p, "match", "recognize.probes")?)?;
            (Some(f), Some(m))
        } else {
            (None, None)
        };
        probes.push(Probe {
            kind,
            call,
            port,
            field,
            matcher,
        });
    }
    Ok(Recognize {
        images,
        binaries,
        units,
        ports,
        probes,
    })
}

fn parse_version(
    id: &str,
    t: &Table,
    up: &Upstream,
    rec: &Recognize,
    has_todo: &dyn Fn(&str) -> bool,
) -> R<Version> {
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
    let source = Source::from_key(v, "source", "version")?;
    let call_table = table(v, "call", "version")?;
    check_keys(
        call_table,
        "version.call",
        &["field"],
        &["argv", "run_as", "method", "path", "accept"],
    )?;
    let field = check_field(call_table, "version.call")?;
    let call = parse_call(
        call_table,
        call_form(source.as_str()),
        "version.call",
        &rec.binaries,
    )?;
    let credential = line(v, "credential", "version")?.to_string();
    no_endpoint_text("version.credential", &credential, true)?;
    let scheme = Scheme::from_key(v, "scheme", "version")?;
    // A network source names its port, or the entry says in `todo` that ports are open.
    let network = matches!(
        source,
        Source::Rpc | Source::Grpc | Source::Http | Source::Nip11
    );
    let endpoint_port = if network {
        match v.get("endpoint_port") {
            Some(Value::Integer(p))
                if port_number(*p).is_some_and(|x| rec.ports.iter().any(|q| q.port == x)) =>
            {
                port_number(*p)
            }
            Some(_) => return Err("version.endpoint_port must be one of recognize.ports".into()),
            None if has_todo("ports:") => None,
            None => {
                return Err(
                    "version.endpoint_port is missing and review.todo has no `ports:` item".into(),
                );
            }
        }
    } else if v.contains_key("endpoint_port") {
        return Err("version.endpoint_port is only for network sources".into());
    } else {
        None
    };
    // TLS: a grpc source says where the certificate comes from and the name it must
    // carry. There is no way to switch verification off: unknown keys fail.
    let tls = if source == Source::Grpc {
        let tls = table(v, "tls", "version")?;
        check_keys(tls, "version.tls", &["cert_source", "server_name"], &[])?;
        let cert_source = CertSource::from_key(tls, "cert_source", "version.tls")?;
        let name = line(tls, "server_name", "version.tls")?;
        no_endpoint_text("version.tls.server_name", name, true)?;
        // A bare local name: `localhost` or this entry's own id, never a public DNS name.
        if name != "localhost" && name != id {
            return Err(format!(
                "version.tls.server_name must be `localhost` or the entry id, not `{name}`"
            ));
        }
        Some(Tls {
            cert_source,
            server_name: name.to_string(),
        })
    } else if v.contains_key("tls") {
        return Err("version.tls is only for grpc sources".into());
    } else {
        None
    };
    let regex = string(v, "regex", "version")?.to_string();
    let pattern = Pattern::new_version(&regex)?;
    let example_tables = tables(v, "examples", "version")?;
    if example_tables.is_empty() {
        return Err("version.examples needs at least one example".into());
    }
    let mut examples = Vec::new();
    for e in example_tables {
        check_keys(
            e,
            "version.examples",
            &["raw", "version", "source"],
            &["source_kind"],
        )?;
        let src = line(e, "source", "version.examples")?;
        check_source(id, up, "version.examples.source", src)?;
        let raw = string(e, "raw", "version.examples")?;
        let want = line(e, "version", "version.examples")?;
        let advisory = e.contains_key("source_kind");
        if advisory {
            // An advisory-derived example: the version form comes from an
            // advisory's affected or fixed value, so it proves the regex reads
            // that form, not that a product ever sent it. It is marked, points at
            // the advisory file, and the entry says in `todo` it awaits a recording.
            // That the file lists the version is checked in tests/catalog.rs.
            one_of(e, "source_kind", "version.examples", &["advisory"])?;
            if !is_advisory_file(src) {
                return Err(format!(
                    "version.examples.source of an advisory example must be an advisory file in the repo: {src}"
                ));
            }
            if raw != want {
                return Err(format!(
                    "an advisory example is the bare value: raw `{raw}` must equal version `{want}`"
                ));
            }
            if !has_todo("recorded-reply:") {
                return Err(
                    "an advisory example needs a `recorded-reply:` item in review.todo".into(),
                );
            }
        }
        let got = pattern.version(raw);
        if got != Some(want) {
            return Err(format!(
                "version.regex on example `{raw}` gives {got:?}, expected `{want}`"
            ));
        }
        examples.push(Example {
            raw: raw.to_string(),
            version: want.to_string(),
            source: src.to_string(),
            advisory,
        });
    }

    // No version regex reads plain versions of more than one major number: that would claim
    // any product's reply. A reviewed exception must still need it.
    let advisory_only = examples.iter().all(|e| e.advisory);
    let majors = major_sweep().iter().filter(|p| pattern.matches(p)).count();
    let excepted = PLAIN_VERSION_OK.iter().any(|(e, _)| *e == id);
    if majors > 1 && !excepted {
        return Err(format!(
            "version.regex reads plain versions of more than one major number, so it would claim any product's reply: {regex}"
        ));
    }
    if majors <= 1 && excepted {
        return Err(format!(
            "`{id}` is in PLAIN_VERSION_OK but its regex no longer reads many majors: remove it"
        ));
    }
    // With no recorded reply there is nothing to recognise the product by: no image,
    // probe or port yet. They arrive when a recorded example replaces the advisory one.
    if advisory_only && (!rec.images.is_empty() || !rec.probes.is_empty() || !rec.ports.is_empty())
    {
        return Err(
            "an entry whose examples are all advisory-derived has no images, probes or ports yet"
                .into(),
        );
    }
    Ok(Version {
        source,
        credential,
        regex,
        scheme,
        endpoint_port,
        tls,
        call: VersionCall { field, call },
        examples,
        pattern,
    })
}

fn parse_advisories(id: &str, t: &Table, up: &Upstream) -> R<Advisories> {
    let adv = table(t, "advisories", "entry")?;
    check_keys(
        adv,
        "advisories",
        &["osv_packages", "ghsa", "feeds"],
        &["blind_spot"],
    )?;
    let osv_packages = strings(adv, "osv_packages", "advisories")?;
    for p in &osv_packages {
        let ok = p
            .split_once(' ')
            .is_some_and(|(eco, name)| !eco.is_empty() && !name.is_empty() && !name.contains(' '));
        if !ok {
            return Err(format!("osv package `{p}` must be `<ECOSYSTEM> <name>`"));
        }
    }
    let ghsa = boolean(adv, "ghsa", "advisories")?;
    let mut machine_feed = false;
    let mut feeds = Vec::new();
    for f in tables(adv, "feeds", "advisories")? {
        check_keys(f, "advisories.feeds", &["kind", "url"], &[])?;
        let kind = one_of(f, "kind", "advisories.feeds", &FEED_KINDS)?;
        machine_feed |= MACHINE_FEEDS.contains(&kind);
        let url = string(f, "url", "advisories.feeds")?;
        check_under_upstream(id, up, "advisories.feeds.url", url)?;
        feeds.push(Feed {
            kind: kind.to_string(),
            url: url.to_string(),
        });
    }
    let blind_spot = opt_line(adv, "blind_spot", "advisories")?;
    if blind_spot.is_none() && !ghsa && !machine_feed {
        return Err("advisories: no GHSA and no feed a machine can read needs a blind_spot".into());
    }
    Ok(Advisories {
        osv_packages,
        ghsa,
        feeds,
        blind_spot,
    })
}

fn parse_signing(
    id: &str,
    t: &Table,
    up: &Upstream,
    has_todo: &dyn Fn(&str) -> bool,
) -> R<Signing> {
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
    let level = one_of(sg, "level", "signing", &LEVELS)?.to_string();
    let method = opt_line(sg, "method", "signing")?;
    let keys_url = if sg.contains_key("keys_url") {
        let u = string(sg, "keys_url", "signing")?;
        check_under_upstream(id, up, "keys_url", u)?;
        Some(u.to_string())
    } else {
        None
    };
    let min_signatures = if sg.contains_key("min_signatures") {
        match sg.get("min_signatures") {
            Some(Value::Integer(n)) if *n >= 1 => u32::try_from(*n).ok(),
            _ => None,
        }
        .ok_or("signing.min_signatures must be a whole number from 1")
        .map(Some)?
    } else {
        None
    };
    if level == "signed-multi" && min_signatures.is_none() && !has_todo("signing.min_signatures") {
        return Err(
            "signed-multi needs signing.min_signatures or a `signing.min_signatures` todo".into(),
        );
    }
    let reproducible = if sg.contains_key("reproducible") {
        Some(one_of(sg, "reproducible", "signing", &REPRODUCIBLE)?.to_string())
    } else {
        None
    };
    let images_signed = if sg.contains_key("images_signed") {
        Some(boolean(sg, "images_signed", "signing")?)
    } else {
        None
    };
    let mut keys = Vec::new();
    for k in tables(sg, "keys", "signing")? {
        check_keys(k, "signing.keys", &["who", "fingerprint", "checked"], &[])?;
        let who = line(k, "who", "signing.keys")?.to_string();
        let fp = string(k, "fingerprint", "signing.keys")?;
        if fp.len() != 40 || !fp.chars().all(|c| c.is_ascii_hexdigit()) {
            return Err("signing.keys.fingerprint must be 40 hex characters".into());
        }
        let checked = date_string(k, "checked", "signing.keys.checked")?;
        keys.push(SigningKey {
            who,
            fingerprint: fp.to_string(),
            checked,
        });
    }
    Ok(Signing {
        level,
        method,
        keys_url,
        min_signatures,
        reproducible,
        images_signed,
        keys,
    })
}

// ---------- cross-entry checks ----------

fn check_unique(entries: &BTreeMap<String, Entry>) -> R<()> {
    let mut seen: BTreeMap<&str, &str> = BTreeMap::new();
    for (id, e) in entries {
        let names = std::iter::once(id.as_str()).chain(e.aliases.iter().map(String::as_str));
        for n in names {
            if let Some(other) = seen.insert(n, id) {
                return Err(format!("`{n}` is used by both `{other}` and `{id}`"));
            }
        }
    }
    Ok(())
}

/// Images are disjoint across entries; ports are too, except the exact SHARED_PORTS.
fn check_disjoint(entries: &BTreeMap<String, Entry>) -> R<()> {
    let mut images: Vec<(&str, &str)> = Vec::new();
    let mut ports: BTreeMap<(u16, Proto), BTreeSet<&str>> = BTreeMap::new();
    for (id, e) in entries {
        for i in &e.recognize.images {
            images.push((i, id));
        }
        for p in &e.recognize.ports {
            ports.entry((p.port, p.proto)).or_default().insert(id);
        }
    }
    for (i, (a, ida)) in images.iter().enumerate() {
        for (b, idb) in images.iter().skip(i + 1) {
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
    let mut per_port: BTreeMap<u16, BTreeSet<&str>> = BTreeMap::new();
    for ((port, _), ids) in &ports {
        per_port
            .entry(*port)
            .or_default()
            .extend(ids.iter().copied());
    }
    for (port, ids) in &per_port {
        if ids.len() > CATALOG_MAX_PRODUCTS_PER_PORT {
            return Err(format!(
                "port {port} is in recognize.ports of {} entries, more than CATALOG_MAX_PRODUCTS_PER_PORT ({CATALOG_MAX_PRODUCTS_PER_PORT})",
                ids.len()
            ));
        }
    }
    for ((port, proto), ids) in &ports {
        let allowed = SHARED_PORTS
            .iter()
            .any(|(p, pr, _)| p == port && *pr == proto.as_str());
        if ids.len() > 1 && !allowed {
            return Err(format!(
                "port {port}/{} is listed by more than one entry {ids:?} and is not in SHARED_PORTS",
                proto.as_str()
            ));
        }
    }
    Ok(())
}

/// `fork_of` and `bundles` name existing entries, never themselves, never in a cycle.
fn check_links(entries: &BTreeMap<String, Entry>) -> R<()> {
    let mut edges: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for (id, e) in entries {
        let targets: Vec<&str> = e
            .fork_of
            .iter()
            .chain(e.bundles.iter())
            .map(String::as_str)
            .collect();
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
    ) -> R<()> {
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

/// The (id, text) list `embedded` loads, sorted by id. A test checks it is
/// exactly the `catalog/` folder.
#[must_use]
pub fn embedded_files() -> &'static [(&'static str, &'static str)] {
    FILES
}
