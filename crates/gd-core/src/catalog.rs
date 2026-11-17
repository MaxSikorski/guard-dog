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

use crate::Untrusted;
use crate::catalog_files::FILES;
use crate::catalog_scan::credential_line;

/// The 1-based line of the first credential-shaped text in `text` (comments
/// included, a secret split across comment lines too), or 0 when there is none.
/// The same `const fn` runs at compile time on every embedded file.
pub use crate::catalog_scan::credential_line as raw_credential_line;

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
pub const OTHER_URLS: [(&str, &str, &str); 1] = [(
    "lnd",
    "advisories.feeds.url",
    // Lightning Labs' advisory site and Atom feed (spike d).
    "https://security.lightning.engineering/",
)];

/// Entries whose `related_repos` may name another owner on the same code host,
/// as (entry id, owner, reason). Every other entry's related repos share the
/// owner of `upstream.repo`.
pub const RELATED_OTHER_OWNER: [(&str, &str, &str); 1] = [(
    "bitcoin-core",
    "bitcoin-core",
    "the signature repo and the project site repo live in the bitcoin-core organisation; the code is in bitcoin",
)];

/// Code hosts an `upstream.repo` or related repo may be on. Add one with a
/// reason and its path shapes in `trust_path_ok`.
pub const FORGE_HOSTS: [&str; 2] = ["github.com", "codeberg.org"];

/// Hosts that carry many projects: a website there must be exactly the repo.
const CODE_HOSTS: [&str; 1] = ["codeberg.org"];

/// Hosts (and all their subdomains) where anyone can publish: never a project's
/// website. `github.com` covers gist and the rest; raw content is its own name.
const SHARED_SITE_HOSTS: [&str; 5] = [
    "github.com",
    "githubusercontent.com",
    "gitlab.com",
    "bitbucket.org",
    "readthedocs.io",
];

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

/// OSV's ecosystem names an `osv_packages` item may start with.
const OSV_ECOSYSTEMS: [&str; 15] = [
    "Go",
    "PyPI",
    "npm",
    "crates.io",
    "GIT",
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

/// Most entries that may list the same port in `recognize.ports`. Equals the
/// fact model's `MAX_CANDIDATES`, by definition (how many products one endpoint
/// may be matched against), so the catalog can never hand the scanner more
/// candidates than a fact can hold. [`load_all`] refuses a catalog over it.
pub const CATALOG_MAX_PRODUCTS_PER_PORT: usize = crate::MAX_CANDIDATES;
const _: () = assert!(CATALOG_MAX_PRODUCTS_PER_PORT == crate::MAX_CANDIDATES);

/// Largest entry text, in bytes (the largest today is under 3 KB).
const MAX_ENTRY_BYTES: usize = 32 * 1024;
/// Most items in any list of an entry (the longest today has 15).
const MAX_LIST: usize = 64;
/// Most `recognize.images` items in one entry.
const MAX_IMAGES: usize = 16;
/// Most entries in a catalog, and most images across all of them.
const MAX_ENTRIES: usize = 1024;

/// Size limit for any regex that runs on untrusted text.
const REGEX_SIZE_LIMIT: usize = 100_000;
/// Longest pattern.
const MAX_PATTERN: usize = 200;
/// Longest reply a catalog pattern is ever run on. Longer replies never match.
pub const MAX_REPLY: usize = 256;

// ---------- errors ----------

/// Why an entry, or the catalog as a whole, was refused.
///
/// One redaction rule: the `Display` and `Debug` of every loader error carry
/// only the file slug, entry ids taken from validated file names, field paths
/// built from `KNOWN_KEYS`, item indexes, line numbers and fixed text; never a
/// value from an entry.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct CatalogError {
    entry: Option<String>,
    message: String,
}

impl CatalogError {
    fn entry(name: &str, message: String) -> Self {
        Self {
            // `name` comes from the caller: only a slug is ever shown.
            entry: Some(if is_slug(name) { name } else { "<entry>" }.to_string()),
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
        /// A certificate pinned in Guard Dog's config.
        PinnedInConfig = "pinned-in-config",
    }
}

/// The shape of a structured, read-only call. Never a shell string.
#[derive(Clone, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum CallKind {
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

/// A call the loader checked: read-only, on [`READ_ONLY_CALLS`], with no shell,
/// host or address in it. Only the loader can make one; code outside this
/// module can read it but not forge it.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Call(CallKind);

impl Call {
    /// What the call is.
    #[must_use]
    pub fn kind(&self) -> &CallKind {
        &self.0
    }

    /// The call as [`READ_ONLY_CALLS`] spells it: (form, descriptor).
    #[must_use]
    pub fn descriptor(&self) -> (&'static str, String) {
        match &self.0 {
            CallKind::Cli { argv, .. } => ("cli", argv.join(" ")),
            CallKind::Http { path, .. } => ("http", format!("GET {path}")),
            CallKind::Rpc { method } => ("rpc", method.clone()),
            CallKind::Grpc { method } => ("grpc", method.clone()),
        }
    }
}

/// A token is a version only if it is 1 to 64 characters of `[0-9A-Za-z.+~-]`
/// and starts with a letter or digit (so `--rpc-file` and `..` are never versions).
fn is_version_token(s: &str) -> bool {
    (1..=64).contains(&s.len())
        && s.chars().next().is_some_and(|c| c.is_ascii_alphanumeric())
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '+' | '~' | '-'))
}

/// A regex that runs on a service's reply. Anchored as `\A(?:pattern)\z`, at
/// most 200 characters, no inline flags, a size limit on the compiled program,
/// compiled with Unicode off where the pattern allows it, and only ever run on
/// replies of at most [`MAX_REPLY`] bytes that are pure ASCII. The reply is
/// [`Untrusted`]; what comes out is a validated version token, never raw reply
/// text.
#[derive(Clone, Debug)]
pub struct Pattern {
    re: Regex,
    /// The majors a plain version (`1.2`, `28.1.0`) may have when this pattern
    /// reads one. `Some` for every loaded entry outside `PLAIN_VERSION_OK` (an
    /// empty set means no bare plain reply is read), `None` only for those
    /// exceptions and for patterns built outside the loader.
    majors: Option<BTreeSet<u64>>,
}

/// Is the whole text `^\d+(\.\d+)*$`: digit runs separated by single dots?
fn is_bare_numeric(text: &str) -> bool {
    !text.is_empty()
        && text
            .split('.')
            .all(|p| !p.is_empty() && p.bytes().all(|b| b.is_ascii_digit()))
}

/// Is this first path segment a registry host? It holds `.` or `:`, or is
/// `localhost`. The one rule for validation and normalisation.
fn is_registry_segment(first: &str) -> bool {
    first.contains(['.', ':']) || first == "localhost"
}

/// The leading number of a plain version: two or more dot-separated runs of
/// ASCII digits and nothing else (`28.1.0`). A number too big for `u64` reads as
/// `u64::MAX`. `None` when the token is not a plain version.
fn plain_major(token: &str) -> Option<u64> {
    let mut parts = token.split('.');
    let first = parts.next()?;
    let mut rest = 0usize;
    for p in parts {
        if p.is_empty() || !p.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        rest += 1;
    }
    if rest == 0 || first.is_empty() || !first.bytes().all(|b| b.is_ascii_digit()) {
        return None;
    }
    Some(first.parse::<u64>().unwrap_or(u64::MAX))
}

impl Pattern {
    /// Compiles a pattern that starts with `^` and ends with an unescaped `$`.
    ///
    /// # Errors
    /// The reason, when the pattern is unanchored, too long, uses inline flags
    /// or does not compile within the size limit.
    pub fn new(pattern: &str) -> Result<Self, String> {
        untrusted_regex(pattern).map(|re| Self { re, majors: None })
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

    /// Can the reply be matched at all? Only when it is at most [`MAX_REPLY`]
    /// bytes and ASCII; otherwise why not.
    fn readable(reply: &str) -> Result<(), Unreadable> {
        if reply.len() > MAX_REPLY {
            Err(Unreadable::TooLong)
        } else if !reply.is_ascii() {
            Err(Unreadable::NonAscii)
        } else {
            Ok(())
        }
    }

    /// Does the whole reply match? A reply over [`MAX_REPLY`] bytes, or with
    /// any non-ASCII character, is [`ReplyMatch::Unreadable`], never `NoMatch`.
    pub fn matches(&self, reply: &Untrusted<String>) -> ReplyMatch<()> {
        // expose_untrusted: matched by an anchored, bounded regex; nothing is returned.
        let text = reply.expose_untrusted();
        if let Err(why) = Self::readable(text) {
            return ReplyMatch::Unreadable(why);
        }
        if self.re.is_match(text) {
            ReplyMatch::Read(())
        } else {
            ReplyMatch::NoMatch
        }
    }

    /// The `version` group of a whole-reply match, when it is a valid version
    /// token (1 to 64 of `[0-9A-Za-z.+~-]`, starting with a letter or digit).
    /// A reply over [`MAX_REPLY`] bytes or a non-ASCII one is
    /// [`ReplyMatch::Unreadable`]; so is a match whose `version` group is not a
    /// valid token. A reply that does not match is `NoMatch`.
    pub fn version<'a>(&self, reply: &'a Untrusted<String>) -> ReplyMatch<&'a str> {
        // expose_untrusted: only a token that passes `is_version_token` leaves this function.
        let text = reply.expose_untrusted();
        if let Err(why) = Self::readable(text) {
            return ReplyMatch::Unreadable(why);
        }
        let Some(caps) = self.re.captures(text) else {
            return ReplyMatch::NoMatch;
        };
        match caps.name("version").map(|m| m.as_str()) {
            Some(v) if is_version_token(v) => {
                // A plain version must have a major the entry permits, however the
                // regex is spelled.
                // A reply is bare when the version group is the whole reply: an
                // empty set then refuses it, and leaves prefixed replies alone.
                // "Bare" is decided from the whole reply (`^\d+(\.\d+)*$`), never
                // from the capture: a regex may drop a leading component.
                let bare = is_bare_numeric(text);
                let major = if bare {
                    plain_major(text)
                } else {
                    plain_major(v)
                };
                match (&self.majors, major) {
                    (Some(set), Some(m)) if !set.contains(&m) && (bare || !set.is_empty()) => {
                        ReplyMatch::Unreadable(Unreadable::NotAVersion)
                    }
                    _ => ReplyMatch::Read(v),
                }
            }
            _ => ReplyMatch::Unreadable(Unreadable::BadToken),
        }
    }
}

/// Why a reply could not be read at all.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Unreadable {
    /// Longer than [`MAX_REPLY`] bytes.
    TooLong,
    /// Has a non-ASCII character.
    NonAscii,
    /// The reply matched, but what the `version` group read is not a valid
    /// version token (or an image reference is not well formed).
    BadToken,
    /// The product was identified, but its version reply is not in a form the
    /// entry reads (empty, a release candidate the regex skips, an unknown build).
    NotAVersion,
    /// No identity evidence fits this read: the wrong number of probe replies,
    /// no identity probe, an entry with no images to identify by, evidence of a
    /// kind this version source cannot use, or evidence taken from a different
    /// endpoint or image than the reply it is used with.
    MissingEvidence,
}

/// The result of running a catalog pattern on a service's reply.
///
/// **`Unreadable` must surface as "version unknown", never as "not affected".**
/// A reply that could not be read says nothing about the product, so no caller
/// may treat it as `NoMatch` (a reply that was read and is not this product's).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub enum ReplyMatch<T> {
    /// The reply matched; `T` is the validated version token (or `()` for a
    /// pattern that reads no version).
    Read(T),
    /// The reply was read and does not match.
    NoMatch,
    /// The reply could not be read; see [`Unreadable`].
    Unreadable(Unreadable),
}

impl<T> ReplyMatch<T> {
    /// The token of a `Read` result, otherwise `None`. A `None` here does not
    /// say which of `NoMatch` or `Unreadable` it was: check that before
    /// treating it as anything but unknown.
    #[must_use]
    pub fn read(self) -> Option<T> {
        match self {
            Self::Read(t) => Some(t),
            _ => None,
        }
    }

    /// Is this `Read`?
    #[must_use]
    pub fn is_read(&self) -> bool {
        matches!(self, Self::Read(_))
    }
}

/// The result of reading a version from an identified product. There is no
/// `NoMatch`: only identity can say "not this product".
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[must_use]
pub enum VersionMatch<'a> {
    /// The validated version token.
    Read(&'a str),
    /// The version is unknown; see [`Unreadable`]. The product is kept.
    Unreadable(Unreadable),
}

impl<'a> VersionMatch<'a> {
    /// The token of a `Read` result, otherwise `None`.
    #[must_use]
    pub fn read(self) -> Option<&'a str> {
        match self {
            Self::Read(t) => Some(t),
            Self::Unreadable(_) => None,
        }
    }

    /// Is this `Read`?
    #[must_use]
    pub fn is_read(&self) -> bool {
        matches!(self, Self::Read(_))
    }
}

/// How a product was identified.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum IdentifiedBy {
    /// The entry's probes matched on the version endpoint.
    Probes,
    /// The container image matched one of `recognize.images`.
    Image,
}

/// Which observation a piece of evidence came from: one host and port, or one
/// container as its runtime reports it. The caller builds it where it takes the
/// reply, and the same key must go to [`Entry::identify_endpoint`] (or
/// [`Entry::identify_image`]) and [`Identified::read_version`], so identity
/// proved on one endpoint or container is never used to read another's reply.
/// An image proof is bound to the container instance, never to the image name.
/// Opaque: it can be compared, and nothing of its contents can be shown.
#[derive(Clone, PartialEq, Eq)]
pub struct EndpointKey {
    kind: KeyKind,
    id: String,
}

#[derive(Clone, Copy, PartialEq, Eq)]
enum KeyKind {
    Endpoint,
    Container,
}

impl EndpointKey {
    /// The key of a network endpoint (host as the scanner dialled it, and port).
    #[must_use]
    pub fn new(host: &str, port: u16) -> Self {
        Self {
            kind: KeyKind::Endpoint,
            id: format!("ep:{}:{port}", host.to_ascii_lowercase()),
        }
    }

    /// The key of one container, as its runtime reports it. `runtime` names the runtime
    /// (a slug, such as `docker` or `podman`); `container_id` is the runtime's id for the
    /// container (the full id, the same spelling everywhere in one scan). `None` when either
    /// is not well formed: then the caller has no container identity, so version unknown.
    #[must_use]
    pub fn for_container(runtime: &str, container_id: &Untrusted<String>) -> Option<Self> {
        // expose_untrusted: checked for length and characters, then only compared.
        let id = container_id.expose_untrusted();
        let id_ok = (1..=128).contains(&id.len())
            && id
                .bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'));
        if !is_slug(runtime) || !id_ok {
            return None;
        }
        Some(Self {
            kind: KeyKind::Container,
            id: format!("{runtime}\u{0}{id}"),
        })
    }
}

impl fmt::Debug for EndpointKey {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "EndpointKey(..)")
    }
}

/// Proof that one endpoint or container was identified as one entry. Only
/// [`Entry::identify_endpoint`] and [`Entry::identify_image`] make one. It
/// remembers the [`EndpointKey`] of the observation it came from: an image
/// proof is bound to that container instance, never to the image name.
///
/// `Unreadable` from [`Identified::read_version`] is version unknown with the
/// product kept: never not affected, never not installed.
#[derive(Clone)]
pub struct Identified<'e> {
    entry: &'e Entry,
    by: IdentifiedBy,
    key: EndpointKey,
}

impl fmt::Debug for Identified<'_> {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        // The id is a validated slug.
        write!(
            f,
            "Identified {{ entry: {:?}, by: {:?} }}",
            self.entry.id, self.by
        )
    }
}

impl<'e> Identified<'e> {
    /// The entry the product was identified as.
    #[must_use]
    pub fn entry(&self) -> &'e Entry {
        self.entry
    }

    /// How it was identified.
    #[must_use]
    pub fn by(&self) -> IdentifiedBy {
        self.by
    }

    /// Reads the version from a reply, for a product already identified.
    /// `key` is the key of the endpoint (or image) the reply came from; if it
    /// is not the one the product was identified on, `Unreadable(MissingEvidence)`.
    /// The evidence must fit the entry's version source (`rpc`, `grpc`, `http`
    /// and `nip11` need probes; `image-label` and a `cli` run in the container
    /// need the image); otherwise `Unreadable(MissingEvidence)`. The whole reply
    /// must match the entry's anchored regex; a reply that does not is
    /// `Unreadable(NotAVersion)`, a reply over [`MAX_REPLY`] bytes or with
    /// non-ASCII text is `Unreadable(TooLong)` or `Unreadable(NonAscii)`. A read
    /// result is a valid version token. `Unreadable` is version unknown with
    /// the product kept: never not affected, never not installed.
    pub fn read_version<'a>(
        &self,
        key: &EndpointKey,
        reply: &'a Untrusted<String>,
    ) -> VersionMatch<'a> {
        let v = &self.entry.version;
        let fits = match v.source {
            Source::Rpc | Source::Grpc | Source::Http | Source::Nip11 => {
                self.by == IdentifiedBy::Probes
            }
            Source::ImageLabel => self.by == IdentifiedBy::Image,
            Source::Cli => {
                self.by == IdentifiedBy::Image
                    && matches!(
                        v.call.call.as_ref().map(Call::kind),
                        Some(CallKind::Cli {
                            run_as: RunAs::ServiceUserInContainer,
                            ..
                        })
                    )
            }
            Source::PlatformManifest => false,
        };
        if !fits || *key != self.key {
            return VersionMatch::Unreadable(Unreadable::MissingEvidence);
        }
        match v.pattern.version(reply) {
            ReplyMatch::Read(t) => VersionMatch::Read(t),
            ReplyMatch::NoMatch => VersionMatch::Unreadable(Unreadable::NotAVersion),
            ReplyMatch::Unreadable(x) => VersionMatch::Unreadable(x),
        }
    }
}

/// `[upstream]`: where the project lives.
#[derive(Clone, Debug)]
#[non_exhaustive]
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
#[non_exhaustive]
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
    kind: ProbeKind,
    call: Call,
    port: Option<u16>,
    field: String,
    matcher: Pattern,
}

impl Probe {
    /// The kind of call.
    #[must_use]
    pub fn kind(&self) -> ProbeKind {
        self.kind
    }

    /// The call.
    #[must_use]
    pub fn call(&self) -> &Call {
        &self.call
    }

    /// The port it goes to (default: `version.endpoint_port`).
    #[must_use]
    pub fn port(&self) -> Option<u16> {
        self.port
    }

    /// The reply field the pattern reads.
    #[must_use]
    pub fn field(&self) -> &str {
        &self.field
    }

    /// The anchored pattern this probe's field must match. Every probe has one.
    #[must_use]
    pub fn pattern(&self) -> &Pattern {
        &self.matcher
    }

    /// Does the probe's pattern match this reply field? A reply over
    /// [`MAX_REPLY`] bytes or with non-ASCII text is `Unreadable`.
    pub fn matches(&self, reply: &Untrusted<String>) -> ReplyMatch<()> {
        self.matcher.matches(reply)
    }
}

/// `[recognize]`: how to tell the product is there.
#[derive(Clone, Debug)]
#[non_exhaustive]
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
#[non_exhaustive]
pub struct Tls {
    /// Where the certificate comes from.
    pub cert_source: CertSource,
    /// `localhost` or the entry's own id.
    pub server_name: String,
}

/// `[version.call]`.
#[derive(Clone, Debug)]
pub struct VersionCall {
    field: String,
    call: Option<Call>,
}

impl VersionCall {
    /// The reply field read: a plain dotted name.
    #[must_use]
    pub fn field(&self) -> &str {
        &self.field
    }

    /// The call; `None` for `image-label` and `platform-manifest` sources.
    #[must_use]
    pub fn call(&self) -> Option<&Call> {
        self.call.as_ref()
    }
}

/// One `[[version.examples]]` item.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub struct Example {
    /// The reply, as sent. Untrusted text: print it only through
    /// `escape_for_terminal`.
    pub raw: Untrusted<String>,
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
    source: Source,
    credential: String,
    regex: String,
    scheme: Scheme,
    endpoint_port: Option<u16>,
    tls: Option<Tls>,
    call: VersionCall,
    examples: Vec<Example>,
    pattern: Pattern,
}

impl Version {
    /// Where the version is read from.
    #[must_use]
    pub fn source(&self) -> Source {
        self.source
    }

    /// The least-privileged credential, in words.
    #[must_use]
    pub fn credential(&self) -> &str {
        &self.credential
    }

    /// The regex source text.
    #[must_use]
    pub fn regex_source(&self) -> &str {
        &self.regex
    }

    /// How versions compare.
    #[must_use]
    pub fn scheme(&self) -> Scheme {
        self.scheme
    }

    /// The port a network source goes to, one of `recognize.ports`.
    #[must_use]
    pub fn endpoint_port(&self) -> Option<u16> {
        self.endpoint_port
    }

    /// TLS, for a gRPC source.
    #[must_use]
    pub fn tls(&self) -> Option<&Tls> {
        self.tls.as_ref()
    }

    /// The call and the field read from its reply.
    #[must_use]
    pub fn call(&self) -> &VersionCall {
        &self.call
    }

    /// Replies and the versions they give.
    #[must_use]
    pub fn examples(&self) -> &[Example] {
        &self.examples
    }
}

/// One `[[platform_map]]` item.
#[derive(Clone, Debug)]
#[non_exhaustive]
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
#[non_exhaustive]
pub struct Feed {
    /// `atom`, `rss`, `markdown-repo` or `release-notes`.
    pub kind: String,
    /// An https URL under the upstream.
    pub url: String,
}

/// `[advisories]`: where the product's security advisories come from.
#[derive(Clone, Debug)]
#[non_exhaustive]
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
#[non_exhaustive]
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
#[non_exhaustive]
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
#[non_exhaustive]
pub struct Review {
    /// A date, `YYYY-MM-DD`.
    pub last_reviewed: String,
    /// https pages the facts come from.
    pub sources: Vec<String>,
    /// Open questions, never guessed values.
    pub todo: Vec<String>,
}

/// One catalog entry, validated. Only the loader makes one; its fields are read
/// through accessors.
#[derive(Clone, Debug)]
pub struct Entry {
    id: String,
    name: String,
    kind: String,
    aliases: Vec<String>,
    summary: String,
    money: bool,
    licence: String,
    fork_of: Option<String>,
    bundles: Vec<String>,
    upstream: Upstream,
    recognize: Recognize,
    version: Version,
    platform_map: Vec<PlatformMap>,
    advisories: Advisories,
    signing: Signing,
    review: Review,
}

impl Entry {
    /// The slug; equals the file name.
    #[must_use]
    pub fn id(&self) -> &str {
        &self.id
    }

    /// The display name.
    #[must_use]
    pub fn display_name(&self) -> &str {
        &self.name
    }

    /// `service`, `platform`, `device`, `app`, `miner` or `package`.
    #[must_use]
    pub fn kind(&self) -> &str {
        &self.kind
    }

    /// Other names advisories use.
    #[must_use]
    pub fn aliases(&self) -> &[String] {
        &self.aliases
    }

    /// One plain-English line.
    #[must_use]
    pub fn summary(&self) -> &str {
        &self.summary
    }

    /// Does it hold funds or keys, or host software that does?
    #[must_use]
    pub fn money(&self) -> bool {
        self.money
    }

    /// The upstream licence.
    #[must_use]
    pub fn licence(&self) -> &str {
        &self.licence
    }

    /// The entry this one is a fork of.
    #[must_use]
    pub fn fork_of(&self) -> Option<&str> {
        self.fork_of.as_deref()
    }

    /// Entries this product ships; one fact per bundled id.
    #[must_use]
    pub fn bundles(&self) -> &[String] {
        &self.bundles
    }

    /// Where the project lives.
    #[must_use]
    pub fn upstream(&self) -> &Upstream {
        &self.upstream
    }

    /// How to recognise it.
    #[must_use]
    pub fn recognize(&self) -> &Recognize {
        &self.recognize
    }

    /// How platforms package it.
    #[must_use]
    pub fn platform_map(&self) -> &[PlatformMap] {
        &self.platform_map
    }

    /// Where its advisories come from.
    #[must_use]
    pub fn advisories(&self) -> &Advisories {
        &self.advisories
    }

    /// How its releases are signed.
    #[must_use]
    pub fn signing(&self) -> &Signing {
        &self.signing
    }

    /// What was checked.
    #[must_use]
    pub fn review(&self) -> &Review {
        &self.review
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

    /// The probes that identify the product on the version endpoint: those with
    /// no `port` or whose `port` is `version.endpoint_port`, in file order.
    #[must_use]
    pub fn identity_probes(&self) -> Vec<&Probe> {
        self.recognize
            .probes
            .iter()
            .filter(|p| p.port.is_none() || p.port == self.version.endpoint_port)
            .collect()
    }

    /// Does this endpoint belong to this product? `key` names the endpoint, and
    /// `replies[i]` is the field value of `identity_probes()[i]`, taken from that
    /// same host and port, which is where the version call goes, in the same
    /// scan. Any probe that does not match is `NoMatch`; the wrong number of
    /// replies, no identity probe or a source with no endpoint is
    /// `Unreadable(MissingEvidence)`.
    pub fn identify_endpoint(
        &self,
        key: &EndpointKey,
        replies: &[Untrusted<String>],
    ) -> ReplyMatch<Identified<'_>> {
        if key.kind != KeyKind::Endpoint
            || !matches!(
                self.version.source,
                Source::Rpc | Source::Grpc | Source::Http | Source::Nip11
            )
        {
            return ReplyMatch::Unreadable(Unreadable::MissingEvidence);
        }
        let probes = self.identity_probes();
        if probes.is_empty() || probes.len() != replies.len() {
            return ReplyMatch::Unreadable(Unreadable::MissingEvidence);
        }
        let results: Vec<ReplyMatch<()>> = probes
            .iter()
            .zip(replies)
            .map(|(p, r)| p.matches(r))
            .collect();
        if results.iter().any(|r| matches!(r, ReplyMatch::NoMatch)) {
            return ReplyMatch::NoMatch;
        }
        if let Some(ReplyMatch::Unreadable(x)) = results
            .iter()
            .find(|r| matches!(r, ReplyMatch::Unreadable(_)))
        {
            return ReplyMatch::Unreadable(*x);
        }
        ReplyMatch::Read(Identified {
            entry: self,
            by: IdentifiedBy::Probes,
            key: key.clone(),
        })
    }

    /// Does this container image (the reference the container runtime reports)
    /// belong to this product? `key` is the container's own key
    /// ([`EndpointKey::for_container`]): the proof is bound to that container
    /// instance, never to the image name, so a second container of the same
    /// image has to be identified on its own. A key that is not a container key,
    /// or an entry with no images, is `Unreadable(MissingEvidence)` (cannot
    /// tell), never `NoMatch`. A reference that is not well formed under one
    /// strict grammar (`[domain/]path[:tag][@digest]`; see `image_reference_ok`)
    /// is `Unreadable(BadToken)`. The proof carries `key`.
    pub fn identify_image(
        &self,
        key: &EndpointKey,
        image: &Untrusted<String>,
    ) -> ReplyMatch<Identified<'_>> {
        if key.kind != KeyKind::Container || self.recognize.images.is_empty() {
            return ReplyMatch::Unreadable(Unreadable::MissingEvidence);
        }
        // expose_untrusted: checked for length, characters and shape, then normalised and
        // compared with the entry's own image names; nothing is returned.
        let text = image.expose_untrusted();
        if text.len() > MAX_REPLY {
            return ReplyMatch::Unreadable(Unreadable::TooLong);
        }
        if !text.is_ascii() {
            return ReplyMatch::Unreadable(Unreadable::NonAscii);
        }
        if !image_reference_ok(text) {
            return ReplyMatch::Unreadable(Unreadable::BadToken);
        }
        let n = normalise_image(text);
        let hit = self
            .recognize
            .images
            .iter()
            .any(|i| match i.strip_suffix('*') {
                None => *i == n,
                // A wildcard covers one more repo name, never a deeper path.
                Some(prefix) => {
                    n.len() > prefix.len()
                        && n.starts_with(prefix)
                        && n.get(prefix.len()..).is_some_and(|r| !r.contains('/'))
                }
            });
        if hit {
            ReplyMatch::Read(Identified {
                entry: self,
                by: IdentifiedBy::Image,
                key: key.clone(),
            })
        } else {
            ReplyMatch::NoMatch
        }
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
    check_size(text).map_err(|e| CatalogError::entry(name, e))?;
    let t = scanned(text).map_err(|e| CatalogError::entry(name, e))?;
    parse_entry(&t, name).map_err(|e| CatalogError::entry(name, e))
}

/// Parses a file after the secret scans. The raw text (comments included) is
/// scanned first; the decoded values are scanned too, and their message, which
/// names a field path, wins when both find something. So nothing after this
/// ever sees (or reports) a value that looks like a secret.
fn scanned(text: &str) -> R<Table> {
    let raw = raw_secret_shapes(text);
    let t = parse_toml(text);
    if let Ok(t) = &t {
        no_secret_shapes(t)?;
    }
    raw?;
    t
}

fn check_size(text: &str) -> R<()> {
    if text.len() > MAX_ENTRY_BYTES {
        return Err(format!("the entry is larger than {MAX_ENTRY_BYTES} bytes"));
    }
    Ok(())
}

/// Parses TOML. The error names the line only: toml's own message quotes the
/// offending text, which may be a secret.
fn parse_toml(text: &str) -> R<Table> {
    toml::from_str(text).map_err(|e| match e.span() {
        Some(sp) => {
            let upto = text.get(..sp.start).unwrap_or("");
            format!(
                "not valid TOML near line {}",
                upto.matches('\n').count() + 1
            )
        }
        None => "not valid TOML".to_string(),
    })
}

/// Loads every entry, then runs the checks that span entries.
///
/// # Errors
/// The first entry that fails [`load`], a name used twice, an image two
/// entries share, a port shared outside [`SHARED_PORTS`], or a `fork_of` or
/// `bundles` that names a missing entry, itself, or forms a cycle.
pub fn load_all(files: &[(&str, &str)]) -> Result<Catalog, CatalogError> {
    if files.len() > MAX_ENTRIES {
        return Err(CatalogError::whole(format!(
            "the catalog has more than {MAX_ENTRIES} entries"
        )));
    }
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
            // The key is never shown: it is outside text and may be a secret.
            return Err(format!("an unknown key in {ctx}"));
        }
    }
    for k in required {
        if !t.contains_key(*k) {
            return Err(format!("missing key `{k}` in {ctx}"));
        }
    }
    Ok(())
}

/// Every key the catalog format knows. Only these are ever shown in an error or
/// a path; any other key is outside text and shows as `<key>`.
const KNOWN_KEYS: [&str; 71] = [
    "accept",
    "advisories",
    "aliases",
    "app_id",
    "argv",
    "binaries",
    "blind_spot",
    "bundles",
    "call",
    "cert_source",
    "checked",
    "credential",
    "endpoint_port",
    "examples",
    "exposure",
    "feeds",
    "field",
    "fingerprint",
    "fork_of",
    "format",
    "ghsa",
    "id",
    "images",
    "images_signed",
    "keys",
    "keys_url",
    "kind",
    "last_reviewed",
    "level",
    "licence",
    "match",
    "method",
    "min_signatures",
    "money",
    "name",
    "note",
    "osv_packages",
    "path",
    "platform",
    "platform_map",
    "port",
    "ports",
    "probes",
    "proto",
    "raw",
    "recognize",
    "regex",
    "related_repos",
    "release_feed",
    "repo",
    "reproducible",
    "review",
    "run_as",
    "scheme",
    "security_policy",
    "server_name",
    "signing",
    "source",
    "source_kind",
    "sources",
    "summary",
    "tls",
    "todo",
    "units",
    "upstream",
    "url",
    "version",
    "version_rule",
    "website",
    "what",
    "who",
];

/// A TOML key as shown in a path: itself when the format knows it, otherwise a
/// stand-in, so an unknown or quoted key can never smuggle text through.
fn key_label(k: &str) -> String {
    if KNOWN_KEYS.contains(&k) {
        k.to_string()
    } else {
        "<key>".to_string()
    }
}

/// Characters of Unicode category Cf (format) plus the bidi controls: they draw
/// nothing but can hide or reorder text, so they never belong in display text.
fn is_format_char(c: char) -> bool {
    matches!(c as u32,
        0x00AD | 0x0600..=0x0605 | 0x061C | 0x06DD | 0x070F | 0x08E2 | 0x180E
        | 0x200B..=0x200F | 0x202A..=0x202E | 0x2060..=0x2064 | 0x2066..=0x206F
        | 0xFEFF | 0xFFF9..=0xFFFB | 0x110BD | 0x110CD | 0x13430..=0x1343F
        | 0x1BCA0..=0x1BCA3 | 0x1D173..=0x1D17A | 0xE0001 | 0xE0020..=0xE007F)
}

fn string<'a>(t: &'a Table, k: &str, ctx: &str) -> R<&'a str> {
    match t.get(k) {
        Some(Value::String(s)) => Ok(s),
        _ => Err(format!("{ctx}.{k} must be a string")),
    }
}

fn line<'a>(t: &'a Table, k: &str, ctx: &str) -> R<&'a str> {
    let s = string(t, k, ctx)?;
    if s.is_empty() || s.chars().any(|c| c.is_control() || is_format_char(c)) {
        return Err(format!(
            "{ctx}.{k} must be one non-empty line with no control, format or bidi characters"
        ));
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
        Some(Value::Array(a)) if a.len() > MAX_LIST => {
            Err(format!("{ctx}.{k} has more than {MAX_LIST} items"))
        }
        Some(Value::Array(a)) => a
            .iter()
            .map(|v| v.as_table().ok_or(format!("{ctx}.{k} must hold tables")))
            .collect(),
        _ => Err(format!("{ctx}.{k} must be a list of tables")),
    }
}

fn strings(t: &Table, k: &str, ctx: &str) -> R<Vec<String>> {
    match t.get(k) {
        Some(Value::Array(a)) if a.len() > MAX_LIST => {
            Err(format!("{ctx}.{k} has more than {MAX_LIST} items"))
        }
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
    let shapes: [(&'static str, &str); 15] = [
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
        // A rune or other high-entropy token: only when it mixes cases and digits.
        ("high-entropy token", r"[A-Za-z0-9+=_-]{40,}"),
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
        return Err("pattern must be anchored (^...$)".into());
    }
    let slashes = pattern
        .strip_suffix('$')
        .unwrap_or(pattern)
        .chars()
        .rev()
        .take_while(|c| *c == '\\')
        .count();
    if slashes % 2 == 1 {
        return Err("pattern ends in an escaped $, not an anchor".into());
    }
    if pattern.len() > MAX_PATTERN {
        return Err(format!("pattern is longer than {MAX_PATTERN} characters"));
    }
    if fixed()?.inline_flags.is_match(pattern) {
        return Err("pattern must not use inline flags".into());
    }
    // The bare pattern must compile on its own first: a stray `)` would otherwise
    // close the wrapper below and let the rest of the pattern run unanchored.
    RegexBuilder::new(pattern)
        .size_limit(REGEX_SIZE_LIMIT)
        .build()
        .map_err(|_| "pattern does not compile on its own within the size limit".to_string())?;
    let wrapped = format!(r"\A(?:{pattern})\z");
    // Unicode off where the pattern allows it, so `\d` and `\w` are ASCII. A pattern
    // that cannot compile that way (it could match bytes that are not UTF-8) uses
    // Unicode mode; every reply is ASCII-only either way (see `Pattern`).
    if let Ok(re) = RegexBuilder::new(&wrapped)
        .size_limit(REGEX_SIZE_LIMIT)
        .unicode(false)
        .build()
    {
        return Ok(re);
    }
    RegexBuilder::new(&wrapped)
        .size_limit(REGEX_SIZE_LIMIT)
        .build()
        .map_err(|_| "pattern does not compile within the size limit".to_string())
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

/// The path of an https URL: empty, or `("/" segment)+` with one optional
/// trailing `/`. A segment is `[A-Za-z0-9._~-]+`, never `.` or `..`, and never
/// empty, so no backslash, `:`, `;`, `@`, `+`, `//` and the like.
fn url_path_ok(path: &str) -> bool {
    if path.is_empty() || path == "/" {
        return true;
    }
    let body = path.strip_suffix('/').unwrap_or(path);
    let Some(inner) = body.strip_prefix('/') else {
        return false;
    };
    inner.split('/').all(|s| {
        !s.is_empty()
            && s != "."
            && s != ".."
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'.' | b'_' | b'~' | b'-'))
    })
}

/// Splits an https URL into (host, path). Refuses anything else, and internal names.
/// The one URL grammar: the host rules of [`https_split`] and the path rule of
/// [`url_path_ok`].
fn https_parts(url: &str) -> R<(&str, &str)> {
    let (host, path) = https_split(url)?;
    if !url_path_ok(path) {
        return Err("URL path must be /-separated segments of [A-Za-z0-9._~-]".into());
    }
    Ok((host, path))
}

/// The host rules of the URL grammar, with the path left as written (a repo URL
/// has its own, stricter path rule in `check_repo_url`).
fn https_split(url: &str) -> R<(&str, &str)> {
    // No error below quotes the URL: it may carry user info or a token.
    let rest = url.strip_prefix("https://").ok_or("URL must be https")?;
    if !url.is_ascii() {
        return Err("URL must be ASCII".into());
    }
    if rest.contains(['?', '#', '@', ' ']) || url.chars().any(char::is_control) {
        return Err("URL must have no credentials, query, fragment or spaces".into());
    }
    // No percent-encoding at all: `%2e%2e` would hide a `..` from the path checks.
    if rest.contains('%') {
        return Err("URL must not use % encoding".into());
    }
    let (host, path) = rest.split_at(rest.find('/').unwrap_or(rest.len()));
    let host_ok = !host.is_empty()
        && host.contains('.')
        && host
            .chars()
            .all(|c| c.is_ascii_lowercase() || c.is_ascii_digit() || c == '.' || c == '-');
    if !host_ok {
        return Err("URL host must be a lower-case name, no port".into());
    }
    // A trailing dot (`example.com.`) or an empty label (`a..b`) is a different
    // spelling of the same name; refuse it before any host rule looks at it.
    if host.split('.').any(str::is_empty) {
        return Err("URL host must not end in a dot or have an empty label".into());
    }
    if internal_host(host) {
        return Err("URL names an internal host or an IP address".into());
    }
    // Hex and octal spellings of an address (`0x7f.1`), a last label that starts
    // with a digit (`127.1`, `1.2.3.4a`), and punycode labels (look-alike names).
    let last = host.rsplit('.').next().unwrap_or("");
    if host
        .split('.')
        .any(|l| l.starts_with("0x") || l.starts_with("xn--"))
        || last.starts_with(|c: char| c.is_ascii_digit())
    {
        return Err(
            "URL host must not use 0x labels, a digit-led last label or punycode (xn--) labels"
                .into(),
        );
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
    // The host rules only: the owner/repo shape below is stricter than the path grammar.
    let (_, path) = https_split(url)?;
    let name_ok = |s: &str, max: usize| {
        (1..=max).contains(&s.len())
            && s.bytes()
                .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
    };
    let segs: Vec<&str> = path.strip_prefix('/').unwrap_or("").split('/').collect();
    match segs.as_slice() {
        [owner, repo]
            if !path.ends_with('/')
                && name_ok(owner, 39)
                && owner.starts_with(|c: char| c.is_ascii_alphanumeric())
                && name_ok(repo, 100)
                && *repo != "."
                && *repo != ".." =>
        {
            Ok(())
        }
        _ => Err("repo URL must be https://host/owner/repo with forge-style names".into()),
    }
}

/// Is `host` the name `base` or a subdomain of it?
fn on_host(host: &str, base: &str) -> bool {
    host == base || host.ends_with(&format!(".{base}"))
}

/// A website may not sit on a shared host: a code or hosting site that carries
/// many projects (github.com and its subdomains, gist, raw content, gitlab.com,
/// bitbucket.org, readthedocs.io) is refused outright; codeberg.org only when it
/// is exactly the repo; a shared pages host only as the project's own subdomain
/// of the upstream owner.
fn check_website(repo: &str, site: &str) -> R<()> {
    let (host, _) = https_parts(site)?;
    if SHARED_SITE_HOSTS.iter().any(|h| on_host(host, h)) {
        return Err("website must not be on a shared code host (or docs host)".into());
    }
    if CODE_HOSTS.iter().any(|h| on_host(host, h)) && site.trim_end_matches('/') != repo {
        return Err("website on a shared code host must be exactly upstream.repo".into());
    }
    let owner = repo
        .strip_prefix("https://")
        .and_then(|r| r.split('/').nth(1))
        .unwrap_or("")
        .to_ascii_lowercase();
    for suffix in PAGES_SUFFIXES {
        let own = format!("{owner}.{suffix}");
        if on_host(host, suffix) && host != own {
            return Err(
                "website on a shared pages host must be the upstream owner's own subdomain".into(),
            );
        }
    }
    Ok(())
}

/// One path segment of `[A-Za-z0-9._-]`, not `.`.
fn trust_segment(s: &str) -> bool {
    !s.is_empty()
        && s != "."
        && s.chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
}

/// `<ref>`: one segment of `[A-Za-z0-9._-]{1,64}`, shaped like a branch or tag
/// name. Not `.`, not `refs`, `pull` or `HEAD` (any case: pull-request and
/// fork-reachable refs), and not all hex of 4 or more characters (an abbreviated
/// commit, which GitHub also serves from any fork).
fn trust_ref(s: &str) -> bool {
    let all_hex = s.len() >= 4 && s.bytes().all(|b| b.is_ascii_hexdigit());
    s.len() <= 64
        && !s.starts_with(['.', '-'])
        && !s.ends_with('.')
        && !s.to_ascii_lowercase().ends_with(".lock")
        && !all_hex
        && !["refs", "pull", "head"]
            .iter()
            .any(|bad| s.eq_ignore_ascii_case(bad))
        && trust_segment(s)
}

/// Does `rest` (the URL after the matched repo base: empty, or starting with
/// `/`) have a shape that `field` trusts? An issue, pull request, discussion or
/// wiki page is writable by anyone, so it is never a trust root. Fields that
/// only cite a source have no shape rule.
fn trust_path_ok(field: &str, feed_kind: Option<&str>, rest: &str) -> bool {
    const FEEDS: [&str; 3] = ["/releases.atom", "/tags.atom", "/releases.rss"];
    // `/<prefix>/<ref>/<path>`, with the path one or more segments.
    let at_ref = |prefix: &str, with_path: bool| -> bool {
        let Some(r) = rest.strip_prefix(prefix) else {
            return false;
        };
        let segs: Vec<&str> = r.split('/').collect();
        match segs.as_slice() {
            [r0] => !with_path && trust_ref(r0),
            [r0, tail @ ..] => {
                trust_ref(r0) && !tail.is_empty() && tail.iter().all(|t| trust_segment(t))
            }
            [] => false,
        }
    };
    // A ref with an optional path below it, or a required one.
    let tree = |prefix: &str, path_required: bool| -> bool {
        if path_required {
            at_ref(prefix, true)
        } else {
            at_ref(prefix, false) || at_ref(prefix, true)
        }
    };
    match field {
        "upstream.release_feed" => FEEDS.contains(&rest),
        "advisories.feeds.url" => match feed_kind {
            Some("atom" | "rss") => FEEDS.contains(&rest),
            Some("markdown-repo") => {
                rest.is_empty() || tree("/tree/", false) || tree("/src/branch/", false)
            }
            Some("release-notes") => rest == "/releases",
            _ => false,
        },
        "signing.keys_url" => {
            tree("/tree/", true) || tree("/blob/", true) || tree("/src/branch/", true)
        }
        "upstream.security_policy" => {
            tree("/blob/", true) || tree("/src/branch/", true) || rest == "/security/policy"
        }
        _ => true,
    }
}

/// A feed, policy, key, source or advisory URL must sit under the entry's own
/// repo (same owner and repo), a listed related repo, or a reviewed (entry,
/// field, prefix) exception. `website_ok` also lets the project's website
/// vouch for it, unless the website is on a shared pages host. Keys and
/// advisory feeds never accept the website.
fn check_under_upstream(
    id: &str,
    up: &Upstream,
    field: &str,
    feed_kind: Option<&str>,
    url: &str,
    website_ok: bool,
) -> R<()> {
    https_parts(url).map_err(|e| format!("{field}: {e}"))?;
    // (base, is a repo of the entry): a repo's URLs must also have a fixed shape.
    let mut bases: Vec<(&str, bool)> = vec![(&up.repo, true)];
    bases.extend(up.related_repos.iter().map(|r| (r.as_str(), true)));
    if website_ok
        && let Some(w) = up.website.as_deref()
        && let Ok((wh, _)) = https_parts(w)
        && !PAGES_SUFFIXES.iter().any(|s| on_host(wh, s))
    {
        // On a code host the website is the repo itself: it gets the repo's shape rules.
        let on_forge = https_parts(w).is_ok_and(|(h, _)| FORGE_HOSTS.iter().any(|f| on_host(h, f)));
        bases.push((w, on_forge));
    }
    bases.extend(
        OTHER_URLS
            .iter()
            .filter(|(i, f, _)| *i == id && *f == field)
            .map(|(_, _, p)| (*p, false)),
    );
    let mut under_any = false;
    for (b, is_repo) in &bases {
        if !under(url, b) {
            continue;
        }
        under_any = true;
        let rest = url.get(b.trim_end_matches('/').len()..).unwrap_or("");
        if !is_repo || trust_path_ok(field, feed_kind, rest) {
            return Ok(());
        }
    }
    if under_any {
        Err(format!(
            "{field} must be a release feed, a file or folder at a ref, or the security policy page of the repo, never an issue, pull request, discussion or wiki page"
        ))
    } else if website_ok {
        Err(format!(
            "{field} is not under upstream.repo, related_repos or website"
        ))
    } else {
        Err(format!(
            "{field} is not under upstream.repo or related_repos (the website does not vouch for it)"
        ))
    }
}

/// A `source` is a file in the repo, or an https URL under the entry's own
/// upstream. That the file exists is checked where the repo is on disk
/// (`tests/catalog.rs`); here only its form.
fn check_source(id: &str, up: &Upstream, field: &str, src: &str) -> R<()> {
    if src.starts_with("https://") {
        check_under_upstream(id, up, field, None, src, true)
    } else if src.contains("..") || src.starts_with('/') {
        Err(format!(
            "{field} must be a file in the repo or a URL under the upstream"
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
    // The text is never quoted back: it may be a URL with a token in it.
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
            "{label} must not name a scheme, host, user info, `..`, link-local or onion address"
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
                return Err(format!("{ctx}.argv[0] must be a bare program name"));
            }
            if NEVER_RUN.contains(&first.as_str()) {
                return Err(format!(
                    "{ctx}.argv[0] must never run a shell or interpreter"
                ));
            }
            if !binaries.contains(first) {
                return Err(format!("{ctx}.argv[0] is not in recognize.binaries"));
            }
            for (i, a) in argv.iter().enumerate() {
                let bad = a.is_empty()
                    || a.chars().any(|c| {
                        c.is_whitespace() || c.is_control() || ";|&$`<>(){}*?~\\\"'!#".contains(c)
                    });
                if bad {
                    return Err(format!("{ctx}.argv[{i}] must be a plain word, never shell"));
                }
                no_endpoint_text(&format!("{ctx}.argv"), a, true)?;
            }
            Some(Call(CallKind::Cli {
                argv,
                run_as: RunAs::from_key(t, "run_as", ctx)?,
            }))
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
                return Err(format!("{ctx}.path must be a local path like /v1/info"));
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
            Some(Call(CallKind::Http {
                path: path.to_string(),
                accept,
            }))
        }
        "rpc" | "grpc" => {
            let m = string(t, "method", ctx)?;
            let name_ok = (1..=80).contains(&m.len())
                && all_chars(m, |c| {
                    c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '/')
                });
            if !name_ok {
                return Err(format!("{ctx}.method must be a method name"));
            }
            no_endpoint_text(&format!("{ctx}.method"), m, false)?;
            let method = m.to_string();
            Some(Call(if form == "rpc" {
                CallKind::Rpc { method }
            } else {
                CallKind::Grpc { method }
            }))
        }
        _ => None,
    };
    if let Some(c) = &call {
        let (f, d) = c.descriptor();
        if !READ_ONLY_CALLS.iter().any(|(rf, rd)| *rf == f && *rd == d) {
            return Err(format!("{ctx}: the {f} call is not in READ_ONLY_CALLS"));
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
            "{ctx}.field must match [A-Za-z0-9_.]{{1,64}} with no `..`"
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

/// Deepest TOML nesting the loader will walk. Entries are flat; anything deeper is refused.
const MAX_DEPTH: usize = 32;

fn collect_strings(path: &str, v: &Value, depth: usize, out: &mut Vec<(String, String)>) -> R<()> {
    if depth > MAX_DEPTH {
        return Err(format!("{path} is nested deeper than {MAX_DEPTH} levels"));
    }
    match v {
        Value::String(s) => out.push((path.to_string(), s.clone())),
        Value::Array(a) => {
            for (i, x) in a.iter().enumerate() {
                collect_strings(&format!("{path}[{i}]"), x, depth + 1, out)?;
            }
        }
        Value::Table(t) => {
            for (k, x) in t {
                let label = key_label(k);
                let next = if path.is_empty() {
                    label
                } else {
                    format!("{path}.{label}")
                };
                collect_strings(&next, x, depth + 1, out)?;
            }
        }
        _ => {}
    }
    Ok(())
}

/// Paths are built only from plain key names (anything else shows as `<key>`),
/// so no quoted key can imitate this path and borrow the exemption.
fn is_fingerprint_path(path: &str) -> bool {
    path.starts_with("signing.keys[") && path.ends_with("].fingerprint")
}

/// The first secret shape in `s`, by name. The 40-hex shape is left to the caller.
fn shape_hit(fx: &Fixed, s: &str) -> Option<&'static str> {
    for (name, re) in &fx.shapes {
        for m in re.find_iter(s) {
            let flagged = match *name {
                "IPv6 candidate" => is_public_ipv6(m.as_str()),
                "IPv4 address" => !["192.0.2.", "198.51.100.", "203.0.113."]
                    .iter()
                    .any(|p| m.as_str().starts_with(p)),
                // Same rule as the compile-time scan (T13).
                "high-entropy token" => {
                    let t = m.as_str();
                    t.bytes().any(|b| b.is_ascii_uppercase())
                        && t.bytes().any(|b| b.is_ascii_lowercase())
                        && t.bytes().any(|b| b.is_ascii_digit())
                }
                _ => true,
            };
            if flagged {
                return Some(if *name == "IPv6 candidate" {
                    "IPv6 address"
                } else {
                    name
                });
            }
        }
    }
    None
}

fn no_secret_shapes(t: &Table) -> R<()> {
    let fx = fixed()?;
    let mut all = Vec::new();
    for (k, v) in t {
        collect_strings(&key_label(k), v, 0, &mut all)?;
    }
    for (path, s) in all {
        if let Some(name) = shape_hit(fx, &s) {
            return Err(format!("{path} has a secret shape: {name}"));
        }
        // A seed written over several lines of a string: every run of whitespace,
        // newlines included, becomes one space, then the seed shape runs again.
        let flat = s.split_whitespace().collect::<Vec<_>>().join(" ");
        if flat != s && shape_hit(fx, &flat).is_some() {
            return Err(format!("{path} has a secret shape: seed phrase over lines"));
        }
        if fx.forty_hex.is_match(&s) && !is_fingerprint_path(&path) {
            return Err(format!(
                "{path} has a secret shape: 40-hex outside signing.keys.fingerprint"
            ));
        }
    }
    Ok(())
}

/// The same scan over the raw source text, line by line, comments included: a
/// comment is never parsed, but `include_str!` ships it. A 40-hex string is
/// only looked for in a comment (after a `#`), because a key fingerprint may
/// sit in a value; the decoded-value scan covers values. The error names the
/// line number only.
fn raw_secret_shapes(text: &str) -> R<()> {
    let fx = fixed()?;
    for (i, line) in text.lines().enumerate() {
        let n = i + 1;
        if shape_hit(fx, line).is_some() {
            return Err(format!("line {n} has a secret shape"));
        }
        if let Some((_, comment)) = line.split_once('#')
            && fx.forty_hex.is_match(comment)
        {
            return Err(format!("line {n} has a secret shape"));
        }
    }
    // One implementation of the comment stream, shared with the compile-time
    // guard in `catalog_files.rs`.
    let n = credential_line(text);
    if n != 0 {
        return Err(format!("line {n} has a secret shape"));
    }
    Ok(())
}

/// Runs only the secret-shape scan on TOML text: no xpub or xprv, nsec,
/// 12-word seed phrase (also over several lines of a string or of comments),
/// 64-hex or longer string, base64 macaroon, high-entropy token of 40 or more
/// characters mixing cases and digits, onion address, Lightning invoice, Cashu
/// token, GitHub, AWS or `sk-` token, private key block, public IPv4 or IPv6
/// address, or a 40-hex string outside `signing.keys.fingerprint`. [`load`]
/// already runs it.
///
/// # Errors
/// The first value with a secret shape, or text that is not TOML.
pub fn scan_secret_shapes(text: &str) -> Result<(), CatalogError> {
    check_size(text).map_err(CatalogError::whole)?;
    scanned(text).map(|_| ()).map_err(CatalogError::whole)
}

// ---------- images ----------

/// The one image-reference grammar (Docker's distribution grammar, narrowed).
///
/// `reference := name [":" tag] ["@" digest]`, at most [`MAX_REPLY`] bytes.
/// `name := [domain "/"] component ("/" component)*`; the first segment is a
/// domain only when there is more than one segment and it holds `.` or `:` or is
/// `localhost`. `domain := label ("." label)* [":" port]` with
/// `label := [A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?` and `port := [0-9]{1,5}`.
/// `component := [a-z0-9]+ (sep [a-z0-9]+)*` with `sep := "." | "_" | "__" | "-"+`
/// (no upper case in a path). `tag := [A-Za-z0-9_][A-Za-z0-9_.-]{0,127}`.
/// `digest := "sha256:" [0-9a-f]{64} | "sha512:" [0-9a-f]{128}`.
fn image_reference_ok(image: &str) -> bool {
    if image.len() > MAX_REPLY {
        return false;
    }
    let (rest, digest) = match image.split_once('@') {
        Some((r, d)) => (r, Some(d)),
        None => (image, None),
    };
    if digest.is_some_and(|d| !image_digest_ok(d)) {
        return false;
    }
    // A `:` after the last `/` starts the tag (`localhost:5000/a` has none).
    let (name, tag) = match rest.rfind(':') {
        Some(p) if rest.get(p..).is_some_and(|t| !t.contains('/')) => {
            (rest.get(..p).unwrap_or(""), rest.get(p + 1..))
        }
        _ => (rest, None),
    };
    if tag.is_some_and(|t| !image_tag_ok(t)) {
        return false;
    }
    let segs: Vec<&str> = name.split('/').collect();
    let (domain, components) = match segs.split_first() {
        Some((first, rest)) if !rest.is_empty() && is_registry_segment(first) => {
            (Some(*first), rest)
        }
        _ => (None, segs.as_slice()),
    };
    domain.is_none_or(image_domain_ok)
        && !components.is_empty()
        && components.iter().all(|c| image_component_ok(c))
}

fn image_digest_ok(d: &str) -> bool {
    let hex = |h: &str, n: usize| {
        h.len() == n
            && h.bytes()
                .all(|b| b.is_ascii_digit() || matches!(b, b'a'..=b'f'))
    };
    match d.split_once(':') {
        Some(("sha256", h)) => hex(h, 64),
        Some(("sha512", h)) => hex(h, 128),
        _ => false,
    }
}

fn image_tag_ok(t: &str) -> bool {
    let mut bytes = t.bytes();
    t.len() <= 128
        && bytes
            .next()
            .is_some_and(|b| b.is_ascii_alphanumeric() || b == b'_')
        && bytes.all(|b| b.is_ascii_alphanumeric() || matches!(b, b'_' | b'.' | b'-'))
}

fn image_domain_ok(d: &str) -> bool {
    let (host, port) = match d.rsplit_once(':') {
        Some((h, p)) => (h, Some(p)),
        None => (d, None),
    };
    if port.is_some_and(|p| !(1..=5).contains(&p.len()) || !p.bytes().all(|b| b.is_ascii_digit())) {
        return false;
    }
    host.split('.').all(|l| {
        let b = l.as_bytes();
        !b.is_empty()
            && b.iter().all(|c| c.is_ascii_alphanumeric() || *c == b'-')
            && b.first().is_some_and(u8::is_ascii_alphanumeric)
            && b.last().is_some_and(u8::is_ascii_alphanumeric)
    })
}

fn image_component_ok(c: &str) -> bool {
    let b = c.as_bytes();
    let alnum = |x: u8| x.is_ascii_lowercase() || x.is_ascii_digit();
    let mut i = 0;
    loop {
        let start = i;
        while b.get(i).is_some_and(|x| alnum(*x)) {
            i += 1;
        }
        if i == start {
            return false;
        }
        if i == b.len() {
            return true;
        }
        match b.get(i) {
            Some(b'.') => i += 1,
            Some(b'_') => {
                i += 1;
                if b.get(i) == Some(&b'_') {
                    i += 1;
                }
            }
            Some(b'-') => {
                while b.get(i) == Some(&b'-') {
                    i += 1;
                }
            }
            _ => return false,
        }
    }
}

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
    let has_registry = parts.len() > 1 && is_registry_segment(first);
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
    if !body.chars().all(|c| {
        c.is_ascii_lowercase() || c.is_ascii_digit() || matches!(c, '.' | '_' | '/' | ':' | '-')
    }) {
        return Err(
            "image must be in normalised form docker.io/namespace/repo, no tag or digest, `*` only at the end"
                .into(),
        );
    }
    let tail_has_colon = body
        .split_once('/')
        .is_some_and(|(_, rest)| rest.contains(':'));
    if body.contains('*')
        || img.contains(['@', ' '])
        || tail_has_colon
        || normalise_image(img) != img
    {
        return Err(
            "image must be in normalised form docker.io/namespace/repo, no tag or digest, `*` only at the end"
                .into(),
        );
    }
    // A wildcard is the very last character, directly after a whole repo name
    // and one of `-`, `_`, `.` (`docker.io/lightninglabs/lnd-*`): never in the
    // namespace, and never under `library/` (Docker's own images).
    if img.ends_with('*') {
        let segs: Vec<&str> = body.split('/').collect();
        let repo = segs.last().copied().unwrap_or("");
        let named = repo
            .strip_suffix(['-', '_', '.'])
            .is_some_and(|r| r.chars().any(|c| c.is_ascii_alphanumeric()));
        if segs.len() < 3 || segs.iter().any(|s| s.is_empty()) || !named {
            return Err(
                "image wildcard must follow a whole repo name and one of `-`, `_`, `.` in a registry/namespace/repo prefix"
                    .into(),
            );
        }
        if segs.get(1) == Some(&"library") {
            return Err("image wildcard must not sit under library/".into());
        }
    }
    Ok(())
}

/// How many plain versions the sweep generates, at most.
const PLAIN_SWEEP_MAX: usize = 40_000;

/// Plain versions a regex must not read for more than one major: every major 0
/// to 99 as 2-, 3- and 4-part forms with minors and patches 0 to 12 (the
/// 4-part form uses a sample of them to stay small) plus the sampled minors and
/// patches 13, 18, 25, 50, 99, 100 and 123, and, for majors 100 to 999,
/// 2000 to 2099 and a few larger ones (1000, 1024, 4242, 9999, 10000, 65535,
/// 99999, 4294967295), three forms each: `a.0`, `a.1.2` and `a.1.2.3`. A regex
/// that reads these for several majors claims some other product's plain reply,
/// whatever way it is spelled.
fn plain_sweep() -> Vec<String> {
    let mut v = Vec::new();
    let wide: Vec<u32> = (100..=999)
        .chain(2000..=2099)
        .chain([1000, 1024, 4242, 9999, 10000, 65535, 99999, 4_294_967_295])
        .collect();
    for &a in &wide {
        v.push(format!("{a}.0"));
        v.push(format!("{a}.1.2"));
        v.push(format!("{a}.1.2.3"));
    }
    const BIG: [u32; 7] = [13, 18, 25, 50, 99, 100, 123];
    for a in 0..=99u32 {
        for b in 0..=12u32 {
            v.push(format!("{a}.{b}"));
            for c in 0..=12u32 {
                v.push(format!("{a}.{b}.{c}"));
            }
        }
        for b in [0u32, 1, 2, 6, 12] {
            for c in [0u32, 1, 7, 12] {
                for d in [0u32, 1, 5] {
                    v.push(format!("{a}.{b}.{c}.{d}"));
                }
            }
        }
        // Sampled larger minors and patches, so a regex that only reads those is seen too.
        for b in BIG {
            v.push(format!("{a}.{b}"));
            for c in [0u32, 1, 7, 12].into_iter().chain(BIG) {
                v.push(format!("{a}.{b}.{c}"));
            }
        }
        for b in [0u32, 1, 2, 7, 12] {
            for c in BIG {
                v.push(format!("{a}.{b}.{c}"));
            }
        }
    }
    debug_assert!(v.len() <= PLAIN_SWEEP_MAX);
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
        return Err("entry.id must be a slug of at most 40 characters".into());
    }
    if id != stem {
        return Err("entry.id must equal the file name".into());
    }
    let name = line(t, "name", "entry")?.to_string();
    if !name.is_ascii() {
        return Err("entry.name must be ASCII".into());
    }
    if name != name.trim() || name.contains("  ") {
        return Err(
            "entry.name must not start or end with a space or hold two spaces in a row".into(),
        );
    }
    let kind = one_of(t, "kind", "entry", &KINDS)?.to_string();
    let aliases = strings(t, "aliases", "entry")?;
    for a in &aliases {
        if !is_slug(a) {
            return Err("an alias must be a slug".into());
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
    for (i, b) in bundles.iter().enumerate() {
        if !is_slug(b) {
            return Err(format!("entry.bundles[{i}] must be a slug"));
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
            note: opt_line(m, "note", "platform_map")?,
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
        https_parts(s).map_err(|e| format!("review.sources: {e}"))?;
    }
    for item in &todo {
        if item.is_empty() || item.chars().any(|c| c.is_control() || is_format_char(c)) {
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
    check_repo_url(&repo).map_err(|e| format!("upstream.repo: {e}"))?;
    let (repo_host, repo_path) = https_parts(&repo)?;
    if !FORGE_HOSTS.contains(&repo_host) {
        return Err("upstream.repo must be on a reviewed code host (FORGE_HOSTS)".into());
    }
    let repo_owner = repo_path
        .trim_matches('/')
        .split('/')
        .next()
        .unwrap_or("")
        .to_ascii_lowercase();
    let related_repos = strings_opt(up, "related_repos", "upstream")?;
    for r in &related_repos {
        check_repo_url(r).map_err(|e| format!("upstream.related_repos: {e}"))?;
        if *r == repo {
            return Err("related_repos must not repeat upstream.repo".into());
        }
        let (rhost, rpath) = https_parts(r)?;
        let rowner = rpath
            .trim_matches('/')
            .split('/')
            .next()
            .unwrap_or("")
            .to_ascii_lowercase();
        let reviewed = RELATED_OTHER_OWNER
            .iter()
            .any(|(i, o, _)| *i == id && *o == rowner);
        if rhost != repo_host || (rowner != repo_owner && !reviewed) {
            return Err(
                "related_repos must be on the same code host and owner as upstream.repo".into(),
            );
        }
    }
    let website = if up.contains_key("website") {
        let w = string(up, "website", "upstream")?;
        check_website(&repo, w).map_err(|e| format!("upstream.website: {e}"))?;
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
            check_under_upstream(id, &out, &format!("upstream.{f}"), None, u, true)?;
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
    if images.len() > MAX_IMAGES {
        return Err(format!("recognize.images has more than {MAX_IMAGES} items"));
    }
    for (i, img) in images.iter().enumerate() {
        check_image_pattern(img).map_err(|e| format!("recognize.images[{i}]: {e}"))?;
        if let Some(j) = images.iter().position(|x| x == img)
            && j < i
        {
            return Err(format!(
                "recognize.images[{i}] repeats recognize.images[{j}]"
            ));
        }
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
        if let Some(first) = ports
            .iter()
            .position(|q| q.port == port && q.proto == proto)
        {
            return Err(format!(
                "recognize.ports items {first} and {} list the same port and protocol",
                ports.len()
            ));
        }
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
        if !p.contains_key("field") || !p.contains_key("match") {
            return Err(
                "recognize.probes: a probe needs both field and match (a probe with no pattern recognises nothing)"
                    .into(),
            );
        }
        let field = check_field(p, "recognize.probes")?;
        let matcher = Pattern::new(string(p, "match", "recognize.probes")?)
            .map_err(|e| format!("recognize.probes.match: {e}"))?;
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
    // A network source needs an identity check on the endpoint its version is read from.
    if network
        && !rec
            .probes
            .iter()
            .any(|p| p.port.is_none() || p.port == endpoint_port)
    {
        return Err(
            "version: a network source needs a recognize.probes item on version.endpoint_port, the identity check for the endpoint the version is read from"
                .into(),
        );
    }
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
            return Err("version.tls.server_name must be `localhost` or the entry id".into());
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
    let mut pattern = Pattern::new_version(&regex)?;
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
                return Err(
                    "version.examples.source of an advisory example must be an advisory file in the repo"
                        .into(),
                );
            }
            if raw != want {
                return Err(
                    "an advisory example is the bare value: version.examples.raw must equal version.examples.version"
                        .into(),
                );
            }
            if !has_todo("recorded-reply:") {
                return Err(
                    "an advisory example needs a `recorded-reply:` item in review.todo".into(),
                );
            }
        }
        let reply = Untrusted::new(raw.to_string());
        // The reply text is never quoted: only where it is and what came out.
        match pattern.version(&reply) {
            ReplyMatch::Read(got) if got == want => {}
            ReplyMatch::Read(_) => {
                return Err(format!(
                    "version.examples[{}].raw: the regex reads a different version than version.examples[{}].version",
                    examples.len(),
                    examples.len()
                ));
            }
            other => {
                return Err(format!(
                    "version.examples[{}].raw: the regex does not read it ({})",
                    examples.len(),
                    match other {
                        ReplyMatch::Unreadable(_) =>
                            "unreadable: too long, non-ASCII or a bad token",
                        _ => "no match",
                    }
                ));
            }
        }
        examples.push(Example {
            raw: reply,
            version: want.to_string(),
            source: src.to_string(),
            advisory,
        });
    }

    // No version regex reads plain versions (`1.2`, `28.1.0`, `2026.1.0.3`) of more
    // than one major number: that would claim any product's reply. A regex pinned
    // to one major (`^2\.\d+\.\d+$`) is allowed. A reviewed exception must still need it.
    let advisory_only = examples.iter().all(|e| e.advisory);
    // The majors it reads are those the sweep sees, and those of its own plain
    // examples whose raw reply is the bare version (so a regex the sweep misses
    // still has its major counted).
    let mut plain_majors: BTreeSet<u64> = plain_sweep()
        .into_iter()
        .filter(|p| pattern.matches(&Untrusted::new(p.clone())).is_read())
        .filter_map(|p| plain_major(&p))
        .collect();
    for e in &examples {
        if e.raw.expose_untrusted() == &e.version
            && let Some(m) = plain_major(&e.version)
        {
            plain_majors.insert(m);
        }
    }
    let reads_plain = plain_majors.len() > 1;
    let excepted = PLAIN_VERSION_OK.iter().any(|(e, _)| *e == id);
    // A regex that reads one major must pin it as written, so it cannot be a
    // wider regex that the sweep happens to see only one major of.
    if plain_majors.len() == 1
        && !excepted
        && let Some(m) = plain_majors.iter().next()
    {
        let head = format!("^(?P<version>{m}\\.");
        let body_ok = regex
            .strip_prefix(&head)
            .and_then(|r| r.strip_suffix(")$"))
            .is_some_and(|b| !b.contains(['(', ')', '|']) && !b.starts_with(['?', '*', '+', '{']));
        if !body_ok {
            return Err("version.regex reads plain versions of one major, so it must pin that major as written: ^(?P<version>MAJOR\\. then no group or alternation, then )$".into());
        }
    }
    // At match time too: a plain version read must have one of these majors, so no
    // spelling of the regex can read a major the entry does not permit. A regex with
    // a prefix around the version (`/Satoshi:...`, `Nutshell/...`) reads no bare
    // plain reply, so its set may be empty: then no bare plain reply is read at all.
    if !excepted {
        pattern.majors = Some(plain_majors.clone());
    }
    if reads_plain && !excepted {
        return Err(
            "version.regex reads plain versions (like 1.2 or 28.1.0) of more than one major number, so it would claim any product's reply"
                .into(),
        );
    }
    if !reads_plain && excepted {
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
        let Some((eco, name)) = p
            .split_once(' ')
            .filter(|(eco, name)| !eco.is_empty() && !name.is_empty() && !name.contains(' '))
        else {
            return Err("advisories.osv_packages items must be `<ECOSYSTEM> <name>`".into());
        };
        if !OSV_ECOSYSTEMS.contains(&eco) {
            return Err(format!(
                "advisories.osv_packages ecosystem must be one of {OSV_ECOSYSTEMS:?} (OSV's names)"
            ));
        }
        if eco == "GIT" && name != up.repo && !up.related_repos.iter().any(|r| r == name) {
            return Err(
                "advisories.osv_packages: a GIT package must be upstream.repo or one of related_repos"
                    .into(),
            );
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
        check_under_upstream(id, up, "advisories.feeds.url", Some(kind), url, false)?;
        feeds.push(Feed {
            kind: kind.to_string(),
            url: url.to_string(),
        });
    }
    let blind_spot = opt_line(adv, "blind_spot", "advisories")?;
    if osv_packages.is_empty() && blind_spot.is_none() {
        return Err(
            "advisories: no osv_packages needs a blind_spot (an entry nothing can match finds no advisories)"
                .into(),
        );
    }
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
        check_under_upstream(id, up, "signing.keys_url", None, u, false)?;
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
    let mut names: BTreeMap<String, &str> = BTreeMap::new();
    for (id, e) in entries {
        if let Some(other) = names.insert(e.name.to_ascii_lowercase(), id) {
            return Err(format!(
                "display name of `{id}` is the same as `{other}`'s (compared without case)"
            ));
        }
    }
    // Only ids (validated file names) and item indexes are ever shown, never an alias.
    let mut seen: BTreeMap<&str, &str> = BTreeMap::new();
    for (id, e) in entries {
        let names = std::iter::once(id.as_str()).chain(e.aliases.iter().map(String::as_str));
        for (pos, n) in names.enumerate() {
            if let Some(other) = seen.insert(n, id) {
                return Err(match pos.checked_sub(1) {
                    None => format!("`{id}` is already used as a name by `{other}`"),
                    Some(i) => format!("`{id}` aliases item {i} is already used by `{other}`"),
                });
            }
        }
    }
    Ok(())
}

/// Images are disjoint across entries; ports are too, except the exact SHARED_PORTS.
fn check_disjoint(entries: &BTreeMap<String, Entry>) -> R<()> {
    let mut images: Vec<(&str, &str, usize)> = Vec::new();
    let mut ports: BTreeMap<(u16, Proto), BTreeMap<&str, usize>> = BTreeMap::new();
    for (id, e) in entries {
        for (n, i) in e.recognize.images.iter().enumerate() {
            images.push((i, id, n));
        }
        for (n, p) in e.recognize.ports.iter().enumerate() {
            ports
                .entry((p.port, p.proto))
                .or_default()
                .entry(id)
                .or_insert(n);
        }
    }
    if images.len() > MAX_ENTRIES {
        return Err(format!("the catalog lists more than {MAX_ENTRIES} images"));
    }
    for (i, (a, ida, ia)) in images.iter().enumerate() {
        for (b, idb, ib) in images.iter().skip(i + 1) {
            if ida == idb {
                continue;
            }
            let (sa, sb) = (a.trim_end_matches('*'), b.trim_end_matches('*'));
            let overlap = match (a.ends_with('*'), b.ends_with('*')) {
                (false, false) => a == b,
                (true, false) => sb.starts_with(sa),
                (false, true) => sa.starts_with(sb),
                (true, true) => sa.starts_with(sb) || sb.starts_with(sa),
            };
            if overlap {
                return Err(format!(
                    "recognize.images of `{ida}` and `{idb}` overlap (items {ia} and {ib})"
                ));
            }
        }
    }
    let mut per_port: BTreeMap<u16, BTreeMap<&str, usize>> = BTreeMap::new();
    for ((port, _), ids) in &ports {
        let m = per_port.entry(*port).or_default();
        for (id, n) in ids {
            m.entry(id).or_insert(*n);
        }
    }
    // Entries and item indexes are shown, never the port number.
    for ids in per_port.values() {
        if ids.len() > CATALOG_MAX_PRODUCTS_PER_PORT {
            let shown: Vec<String> = ids.iter().map(|(i, n)| format!("`{i}` item {n}")).collect();
            return Err(format!(
                "recognize.ports: one port is listed by {} entries ({}), more than CATALOG_MAX_PRODUCTS_PER_PORT ({CATALOG_MAX_PRODUCTS_PER_PORT})",
                ids.len(),
                shown.join(", ")
            ));
        }
    }
    for ((port, proto), ids) in &ports {
        let allowed = SHARED_PORTS
            .iter()
            .any(|(p, pr, _)| p == port && *pr == proto.as_str());
        if ids.len() > 1 && !allowed {
            let shown: Vec<String> = ids.iter().map(|(i, n)| format!("`{i}` item {n}")).collect();
            return Err(format!(
                "recognize.ports: one port and protocol is listed by more than one entry ({}) and is not in SHARED_PORTS",
                shown.join(", ")
            ));
        }
    }
    Ok(())
}

/// `fork_of` and `bundles` name existing entries, never themselves, never in a cycle.
fn check_links(entries: &BTreeMap<String, Entry>) -> R<()> {
    let mut edges: BTreeMap<&str, Vec<&str>> = BTreeMap::new();
    for (id, e) in entries {
        // Fields and item indexes are shown, never the value.
        let named: Vec<(String, &str)> = e
            .fork_of
            .iter()
            .map(|f| ("fork_of".to_string(), f.as_str()))
            .chain(
                e.bundles
                    .iter()
                    .enumerate()
                    .map(|(i, b)| (format!("bundles item {i}"), b.as_str())),
            )
            .collect();
        let mut targets: Vec<&str> = Vec::new();
        for (field, t) in named {
            if t == id {
                return Err(format!("{id}: {field} names itself"));
            }
            if !entries.contains_key(t) {
                return Err(format!("{id}: {field} does not name an entry"));
            }
            targets.push(t);
        }
        edges.insert(id, targets);
    }
    // Iterative depth-first search with a visited set: no recursion, so a long
    // chain of entries can never overflow the stack. A node on the current
    // path met again is a cycle.
    let mut done: BTreeSet<&str> = BTreeSet::new();
    for start in entries.keys() {
        if done.contains(start.as_str()) {
            continue;
        }
        let mut on_path: BTreeSet<&str> = BTreeSet::new();
        // (node, index of the next edge to follow)
        let mut stack: Vec<(&str, usize)> = vec![(start.as_str(), 0)];
        on_path.insert(start.as_str());
        while let Some((node, i)) = stack.last().copied() {
            let next = edges.get(node).and_then(|v| v.get(i)).copied();
            if let Some(top) = stack.last_mut() {
                top.1 += 1;
            }
            match next {
                Some(n) if on_path.contains(n) => {
                    return Err(format!("fork_of or bundles has a cycle through `{n}`"));
                }
                Some(n) if done.contains(n) => {}
                Some(n) => {
                    on_path.insert(n);
                    stack.push((n, 0));
                }
                None => {
                    on_path.remove(node);
                    done.insert(node);
                    stack.pop();
                }
            }
        }
    }
    Ok(())
}

/// The (id, text) list `embedded` loads, sorted by id. A test checks it is
/// exactly the `catalog/` folder.
#[must_use]
pub fn embedded_files() -> &'static [(&'static str, &'static str)] {
    FILES
}

#[cfg(test)]
#[allow(clippy::unwrap_used, clippy::panic)]
mod tests {
    use super::*;

    fn reply(s: &str) -> Untrusted<String> {
        Untrusted::new(s.to_string())
    }

    #[test]
    fn a_plain_version_must_have_a_permitted_major_at_match_time() {
        // Codex catalog r3 MED 3: `^(?P<version>1\.?12\.7)$` reads `1.12.7` and `112.7`;
        // with the permitted major {1} the second reads nothing.
        let mut p = Pattern::new_version(r"^(?P<version>1\.?12\.7)$").unwrap();
        assert_eq!(p.version(&reply("112.7")), ReplyMatch::Read("112.7"));
        p.majors = Some(BTreeSet::from([1]));
        assert_eq!(p.version(&reply("1.12.7")), ReplyMatch::Read("1.12.7"));
        assert_eq!(
            p.version(&reply("112.7")),
            ReplyMatch::Unreadable(Unreadable::NotAVersion)
        );
        // A token that is not a plain version is not held to the rule.
        let mut q = Pattern::new_version(r"^v(?P<version>\d+\.\d+-beta)$").unwrap();
        q.majors = Some(BTreeSet::from([1]));
        assert_eq!(q.version(&reply("v9.1-beta")), ReplyMatch::Read("9.1-beta"));
        // `(?:1|2)\.19\.0` with only major 1 permitted cannot read 2.19.0.
        let mut r = Pattern::new_version(r"^(?P<version>(?:1|2)\.19\.0)$").unwrap();
        r.majors = Some(BTreeSet::from([1]));
        assert_eq!(r.version(&reply("1.19.0")), ReplyMatch::Read("1.19.0"));
        assert!(!r.version(&reply("2.19.0")).is_read());
        // An empty set refuses every bare plain reply and leaves a prefixed one alone.
        let mut s = Pattern::new_version(r"^v?(?P<version>\d+\.\d+\.\d+)$").unwrap();
        s.majors = Some(BTreeSet::new());
        assert_eq!(
            s.version(&reply("26.6.9")),
            ReplyMatch::Unreadable(Unreadable::NotAVersion)
        );
        assert_eq!(s.version(&reply("v26.6.9")), ReplyMatch::Read("26.6.9"));
        // Helper edge cases.
        assert_eq!(plain_major("28.1.0"), Some(28));
        assert_eq!(plain_major("99999999999999999999.1"), Some(u64::MAX));
        for not in ["28", "28.", ".1", "1..2", "1.2-beta", "v1.2", "", "1.a"] {
            assert_eq!(plain_major(not), None, "{not}");
        }
    }
}
