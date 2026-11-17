//! The fact model: what Guard Dog's sensors saw, as plain data.
//!
//! No IO, no clock, no randomness, so it compiles to WASM for the status page.
//! Four rules shape it:
//!
//! - **Outside text stays [`Untrusted`].** The only trusted strings are the
//!   validated newtypes ([`CatalogId`], [`PlainVersion`], ...), each built only
//!   by a `parse` that refuses anything outside its character set. The raw
//!   reply travels beside them as [`Evidence`].
//! - **Unknown never becomes fine.** [`Observed`] is `Seen` or `Unknown` with
//!   no `Default`, no bool conversion and no equality with the plain value; the
//!   only way to read it is `match`.
//! - **A method, not a confidence number.** [`Method`] is an ordered enum:
//!   digests and signed hashes rank above a service's own report.
//! - **Setup-level facts are derived, never stored** (`view::setup_view`).
//!
//! **The matcher's input** is `Observed<PlainVersion>` (a service's version, or
//! `Observed<Presence>` plus `Observed<PlainVersion>` for a package inside it): it matches only on `Seen`,
//! and `Unknown` can only ever make a result more cautious. A `PlainVersion`
//! also takes a PEP 440 epoch (`1!2.0`); an image digest is the separate
//! [`ImageDigest`] type, never a version.
//!
//! Variants and fields are named as in the design (`1.1-1.2-facts-store-privilege.md`
//! section 1) and documented at the type, hence the `missing_docs` allowance.
#![allow(missing_docs)]

use std::fmt;

use serde::{Deserialize, Serialize};

use crate::Untrusted;

/// Bumped on any breaking change to these types; stored with every scan.
pub const FACT_MODEL: u32 = 1;

/// At most this many pieces of evidence per fact; more are dropped.
pub const MAX_EVIDENCE: usize = 4;
/// Evidence text is cut to this many bytes, marker included.
pub const MAX_EVIDENCE_BYTES: usize = 1024;
/// Detail text on an [`Unknown`] is cut to this many bytes, marker included.
pub const MAX_DETAIL_BYTES: usize = 256;
/// Appended where text was cut, so a reader can see it was.
pub const CUT_MARKER: &str = "[...cut]";

/// A checked string was refused. Says which kind, never the offending text.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct FactError {
    pub what: &'static str,
}

impl fmt::Display for FactError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "not a valid {}", self.what)
    }
}

impl std::error::Error for FactError {}

fn is_slug(text: &str, underscore: bool, empty_ok: bool) -> bool {
    if text.is_empty() {
        return empty_ok;
    }
    text.len() <= 40
        && text.starts_with(|c: char| c.is_ascii_lowercase() || c.is_ascii_digit())
        && text.chars().all(|c| {
            c.is_ascii_lowercase() || c.is_ascii_digit() || c == '-' || (underscore && c == '_')
        })
}

/// The punctuation a version may hold besides letters and digits. One shared
/// definition: `lab/up.sh`'s `plain()` also allows `_ : /`; `:` and `/` are
/// refused here (a version with either becomes a blind spot, never a fact),
/// and `~` is added for Debian-style versions. `!` is allowed only as a PEP 440
/// epoch separator (`1!2.0`), never anywhere else.
pub const VERSION_PUNCTUATION: &str = ".+~_-";
/// The longest version, epoch included.
pub const MAX_VERSION_BYTES: usize = 64;

fn is_plain_version(text: &str) -> bool {
    let plain = |t: &str| {
        !t.is_empty()
            && t.chars()
                .all(|c| c.is_ascii_alphanumeric() || VERSION_PUNCTUATION.contains(c))
    };
    if !(1..=MAX_VERSION_BYTES).contains(&text.len()) {
        return false;
    }
    match text.split_once('!') {
        Some((epoch, rest)) => {
            !epoch.is_empty() && epoch.chars().all(|c| c.is_ascii_digit()) && plain(rest)
        }
        None => plain(text),
    }
}

fn is_lower_hex_64(text: &str) -> bool {
    text.len() == 64 && text.chars().all(|c| matches!(c, '0'..='9' | 'a'..='f'))
}

/// A string type with a validated constructor and nothing else. Serde reads it
/// back through `parse`, so a stored or received value is checked too.
macro_rules! checked_string {
    ($(#[$meta:meta])* $name:ident, $what:literal, $check:expr) => {
        $(#[$meta])*
        #[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Deserialize)]
        #[serde(try_from = "String")]
        pub struct $name(String);

        impl Serialize for $name {
            fn serialize<S: serde::Serializer>(&self, serializer: S) -> Result<S::Ok, S::Error> {
                serializer.serialize_str(&self.0)
            }
        }

        impl $name {
            pub fn parse(text: &str) -> Result<Self, FactError> {
                let check: fn(&str) -> bool = $check;
                if check(text) {
                    Ok(Self(text.to_owned()))
                } else {
                    Err(FactError { what: $what })
                }
            }

            pub fn as_str(&self) -> &str {
                &self.0
            }
        }

        impl TryFrom<String> for $name {
            type Error = FactError;
            fn try_from(text: String) -> Result<Self, FactError> {
                Self::parse(&text)
            }
        }
    };
}

checked_string!(
    /// A catalog id: lower-case letters, digits and `-`, 1 to 40, such as `bitcoin-core`.
    CatalogId, "catalog id", |t| is_slug(t, false, false)
);
checked_string!(
    /// A setting id: like a catalog id, plus `_` (`option_enabled`).
    SettingId, "setting id", |t| is_slug(t, true, false)
);
checked_string!(
    /// A recorded or fixture setup's id (`lab-regtest`).
    SetupId, "setup id", |t| is_slug(t, false, false)
);
checked_string!(
    /// Which instance of a catalog entry: empty for the only one, else a slug.
    InstanceName, "instance name", |t| is_slug(t, false, true)
);
checked_string!(
    /// The name of the call a sensor made (`getnetworkinfo`).
    CallId, "call id", |t| is_slug(t, true, false)
);
checked_string!(
    /// Which plain-English fix text a blind spot points at.
    HintId, "hint id", |t| is_slug(t, true, false)
);
checked_string!(
    /// A version as a service reported it: letters, digits and `VERSION_PUNCTUATION`,
    /// 1 to 64 bytes, with an optional PEP 440 epoch (`1!2.0`).
    PlainVersion, "version", is_plain_version
);
checked_string!(
    /// A SHA-256 as 64 lower-case hex digits.
    Sha256, "sha256", is_lower_hex_64
);
checked_string!(
    /// A container image digest: `sha256:` and 64 lower-case hex digits.
    ImageDigest, "image digest", |t| t
        .strip_prefix("sha256:")
        .is_some_and(is_lower_hex_64)
);

/// Unix seconds. Always passed in, never read from a clock here.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Timestamp(pub i64);

/// Cuts `text` to at most `max` bytes at a character boundary, ending in
/// [`CUT_MARKER`] when anything was cut.
fn cap_text(text: &str, max: usize) -> String {
    if text.len() <= max {
        return text.to_owned();
    }
    let keep = max.saturating_sub(CUT_MARKER.len());
    let mut end = keep;
    while !text.is_char_boundary(end) {
        end = end.saturating_sub(1);
    }
    let mut out = String::with_capacity(max);
    out.push_str(text.get(..end).unwrap_or(""));
    out.push_str(CUT_MARKER);
    out
}

/// Something observed: a value, or a reason there is none. No `Default`, no
/// bool conversion, no `==` against a plain `T`, no `unwrap_or`: the only way
/// to read it is `match`, so a missing value can't quietly turn into "fine".
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Observed<T> {
    Seen(T),
    Unknown(Unknown),
}

/// Why nothing was seen.
#[derive(Clone, Debug, Serialize, Deserialize)]
pub struct Unknown {
    pub reason: UnknownReason,
    pub detail: Option<Untrusted<String>>,
}

impl Unknown {
    pub fn new(reason: UnknownReason) -> Self {
        Self {
            reason,
            detail: None,
        }
    }

    /// With text from outside (an error message), kept untrusted and capped.
    pub fn with_detail(reason: UnknownReason, detail: &str) -> Self {
        Self {
            reason,
            detail: Some(Untrusted::new(cap_text(detail, MAX_DETAIL_BYTES))),
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum UnknownReason {
    NotChecked,
    NoPermission,
    NoReply,
    Unparsable,
    Conflict,
    NotSupportedHere,
    /// Looked for, but the sensor did not cover everything, so "not there" can't be said.
    IncompleteCoverage,
}

/// What a service, host or setup is, and how sure the sensor was.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
pub enum Claim {
    Host {
        os: Untrusted<String>,
        os_version: Observed<PlainVersion>,
        kernel: Observed<PlainVersion>,
        arch: Observed<Arch>,
    },
    /// `docker`, `umbrelos`, ...
    Platform {
        id: CatalogId,
        version: Observed<PlainVersion>,
    },
    Service {
        state: Observed<ServiceState>,
        version: Observed<PlainVersion>,
        runs_as: RunsAs,
        method: Method,
    },
    Unrecognized {
        runs_as: RunsAs,
        version_label: Option<Untrusted<String>>,
        source_label: Option<Untrusted<String>>,
    },
    /// Subject: the node that said it.
    Chain(Observed<Chain>),
    /// Subject: bitcoind's data directory.
    BlockStorage(Observed<FsKind>),
    /// Subject: the service it is inside. A package that is not there at all is
    /// `Seen(Absent)` (complete coverage only); one nobody looked for is `Unknown`.
    Package {
        product: CatalogId,
        presence: Observed<Presence>,
        version: Observed<PlainVersion>,
    },
    Exposure {
        port: u16,
        proto: Proto,
        reach: Observed<Reach>,
    },
    /// `option_enabled`, `backend_in_use`, `feature_enabled`, ...
    Setting {
        key: SettingId,
        value: Observed<SettingValue>,
    },
    BlindSpot {
        area: Area,
        what: BlindSpotKind,
        hint: HintId,
    },
}

impl Claim {
    /// The claim's family, as a stable lower-case word (the store's `kind`).
    pub fn kind(&self) -> &'static str {
        match self {
            Claim::Host { .. } => "host",
            Claim::Platform { .. } => "platform",
            Claim::Service { .. } => "service",
            Claim::Unrecognized { .. } => "unrecognized",
            Claim::Chain(_) => "chain",
            Claim::BlockStorage(_) => "block_storage",
            Claim::Package { .. } => "package",
            Claim::Exposure { .. } => "exposure",
            Claim::Setting { .. } => "setting",
            Claim::BlindSpot { .. } => "blind_spot",
        }
    }
}

/// How completely a sensor looked. Only `Complete` may say something is absent.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Coverage {
    Complete,
    Partial,
}

/// Whether a package is there. `Absent` is a claim, never a gap: it needs a
/// search with complete coverage (`Presence::absent`), and the fact's evidence
/// says what was searched. Judge B's `version = "none"` is `Seen(Absent)`; a
/// package nobody looked for is `Unknown`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Presence {
    Present,
    Absent,
}

impl Presence {
    /// "Looked and it is not there": `Seen(Absent)` for a complete search,
    /// `Unknown(IncompleteCoverage)` for anything less.
    pub fn absent(coverage: Coverage) -> Observed<Presence> {
        match coverage {
            Coverage::Complete => Observed::Seen(Presence::Absent),
            Coverage::Partial => Observed::Unknown(Unknown::new(UnknownReason::IncompleteCoverage)),
        }
    }
}

/// What a service is doing. A stopped container is `Stopped`, never "running
/// because a fact exists"; a service searched for and not found is `NotFound`,
/// built only by `ServiceState::not_found`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServiceState {
    Running,
    Stopped,
    NotFound,
}

impl ServiceState {
    /// `Seen(NotFound)` for a complete search, `Unknown(IncompleteCoverage)` otherwise.
    pub fn not_found(coverage: Coverage) -> Observed<ServiceState> {
        match coverage {
            Coverage::Complete => Observed::Seen(ServiceState::NotFound),
            Coverage::Partial => Observed::Unknown(Unknown::new(UnknownReason::IncompleteCoverage)),
        }
    }
}

/// A package as the view reports it, derived from presence and version.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum PackageState {
    NotInstalled,
    Version(PlainVersion),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum WordSize {
    Bits32,
    Bits64,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum Arch {
    X86_64,
    Aarch64,
    Armv7,
    X86,
    Other(Untrusted<String>),
}

impl Arch {
    /// For Judge B's `arch` family; `None` for an architecture we don't know.
    pub fn word_size(&self) -> Option<WordSize> {
        match self {
            Arch::X86_64 | Arch::Aarch64 => Some(WordSize::Bits64),
            Arch::Armv7 | Arch::X86 => Some(WordSize::Bits32),
            Arch::Other(_) => None,
        }
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Chain {
    Main,
    Testnet3,
    Testnet4,
    Signet,
    Regtest,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum FsKind {
    Ext4,
    Btrfs,
    Xfs,
    Zfs,
    F2fs,
    Fat32,
    Exfat,
    Ntfs,
    Tmpfs,
    Other(Untrusted<String>),
}

/// How far a port reaches, least to most. Judge B's `none` is
/// `Seen(NotListening | Localhost)`.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Reach {
    NotListening,
    Localhost,
    Lan,
    Tunnel,
    Internet,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Proto {
    Tcp,
    Udp,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum SettingValue {
    Enabled,
    Disabled,
    Named(SettingId),
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Area {
    Host,
    Platform,
    Services,
    Chain,
    Exposure,
    Packages,
    Store,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum BlindSpotKind {
    NoPermission,
    NoReply,
    Unparsable,
    TooBig,
    StoredByNewerGuardDog,
    HistorySetAside,
    /// Two detection methods gave different versions; the better one was used.
    MethodsDisagree,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum RunsAs {
    Container {
        name: Untrusted<String>,
        image: Untrusted<String>,
        digest: Option<ImageDigest>,
    },
    Unit {
        name: Untrusted<String>,
    },
    Binary {
        path: Untrusted<String>,
        sha256: Option<Sha256>,
    },
}

/// How a version or identity was found. Declared strongest first, so the
/// derived order says `SignedHash < ImageDigest < ServiceReply < ...`: a
/// smaller method is the better evidence, and a digest or a signed hash ranks
/// above anything a service says about itself (threat model section 6 item 15).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Method {
    SignedHash,
    ImageDigest,
    ServiceReply,
    ImageName,
    Binary,
    Unit,
    Port,
    UserEntered,
}

impl Method {
    /// True when `self` is better evidence than `other`.
    pub fn outranks(self, other: Method) -> bool {
        self < other
    }
}

/// The sensors that can state a fact.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum SensorId {
    DockerProxy,
    BitcoindRpc,
    LndRest,
    ClnRest,
    Nip11,
    Nut06,
    OsRelease,
    Systemd,
    Fixture,
    LabManifest,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Backend {
    Live,
    Recorded { setup: SetupId },
    Fixture { setup: SetupId },
    Fake,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct Source {
    pub sensor: SensorId,
    pub backend: Backend,
}

/// What a fact is about.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum Subject {
    Host,
    Service(InstanceRef),
    Setup,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct InstanceRef {
    pub catalog: CatalogId,
    pub instance: InstanceName,
}

/// The raw reply a fact came from: which call, and its text, untrusted and
/// cut to [`MAX_EVIDENCE_BYTES`] with a visible marker.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(try_from = "EvidenceWire")]
pub struct Evidence {
    call: CallId,
    raw: Untrusted<String>,
}

#[derive(Deserialize)]
struct EvidenceWire {
    call: CallId,
    raw: Untrusted<String>,
}

impl TryFrom<EvidenceWire> for Evidence {
    type Error = FactError;
    fn try_from(wire: EvidenceWire) -> Result<Self, FactError> {
        if wire.raw.byte_len() > MAX_EVIDENCE_BYTES {
            return Err(FactError {
                what: "evidence (over 1 KiB)",
            });
        }
        Ok(Self {
            call: wire.call,
            raw: wire.raw,
        })
    }
}

impl Evidence {
    /// Wraps `raw` as untrusted at once, cutting it to 1 KiB.
    pub fn new(call: CallId, raw: &str) -> Self {
        Self {
            call,
            raw: Untrusted::new(cap_text(raw, MAX_EVIDENCE_BYTES)),
        }
    }

    pub fn call(&self) -> &CallId {
        &self.call
    }

    pub fn raw(&self) -> &Untrusted<String> {
        &self.raw
    }
}

/// One thing a sensor saw. Build it with [`Fact::new`], which keeps at most
/// [`MAX_EVIDENCE`] pieces of evidence.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(from = "FactWire")]
pub struct Fact {
    pub subject: Subject,
    pub claim: Claim,
    pub source: Source,
    pub observed_at: Timestamp,
    evidence: Vec<Evidence>,
}

#[derive(Deserialize)]
struct FactWire {
    subject: Subject,
    claim: Claim,
    source: Source,
    observed_at: Timestamp,
    evidence: Vec<Evidence>,
}

impl From<FactWire> for Fact {
    fn from(wire: FactWire) -> Self {
        Fact::new(
            wire.subject,
            wire.claim,
            wire.source,
            wire.observed_at,
            wire.evidence,
        )
    }
}

impl Fact {
    pub fn new(
        subject: Subject,
        claim: Claim,
        source: Source,
        observed_at: Timestamp,
        mut evidence: Vec<Evidence>,
    ) -> Self {
        evidence.truncate(MAX_EVIDENCE);
        Self {
            subject,
            claim,
            source,
            observed_at,
            evidence,
        }
    }

    pub fn evidence(&self) -> &[Evidence] {
        &self.evidence
    }
}

/// Where a fact's back end sits, without the setup name: Judge B's `source`
/// family (`lab` is `Recorded`, `synthetic` is `Fixture`).
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum BackendKind {
    Live,
    Recorded,
    Fixture,
    Fake,
}

impl Backend {
    pub fn kind(&self) -> BackendKind {
        match self {
            Backend::Live => BackendKind::Live,
            Backend::Recorded { .. } => BackendKind::Recorded,
            Backend::Fixture { .. } => BackendKind::Fixture,
            Backend::Fake => BackendKind::Fake,
        }
    }
}
