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

/// Most catalog products one unrecognised endpoint may list as what it might be.
pub const MAX_CANDIDATES: usize = 32;
/// Evidence text is cut to this many bytes, marker included.
pub const MAX_EVIDENCE_BYTES: usize = 1024;
/// Detail text on an [`Unknown`] is cut to this many bytes, marker included.
pub const MAX_DETAIL_BYTES: usize = 256;
/// Outside text kept in a fact (names, labels) is cut to this many bytes.
pub const MAX_OUTSIDE_TEXT_BYTES: usize = 1024;
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
    // Starts with a letter or digit, so a version can never look like an option
    // (`-x`) or a path (`.`, `..`).
    let plain = |t: &str| {
        t.starts_with(|c: char| c.is_ascii_alphanumeric())
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

/// Why nothing was seen. The detail text is outside text, capped at
/// [`MAX_DETAIL_BYTES`] at construction and refused over it on load.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(try_from = "UnknownWire")]
pub struct Unknown {
    pub reason: UnknownReason,
    detail: Option<Untrusted<String>>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct UnknownWire {
    reason: UnknownReason,
    detail: Option<Untrusted<String>>,
}

impl TryFrom<UnknownWire> for Unknown {
    type Error = FactError;
    fn try_from(wire: UnknownWire) -> Result<Self, FactError> {
        if wire
            .detail
            .as_ref()
            .is_some_and(|d| d.byte_len() > MAX_DETAIL_BYTES)
        {
            return Err(FactError {
                what: "detail (over 256 bytes)",
            });
        }
        Ok(Self {
            reason: wire.reason,
            detail: wire.detail,
        })
    }
}

/// Outside text kept in a fact (an OS name, a container name, a label): always
/// untrusted, cut to [`MAX_OUTSIDE_TEXT_BYTES`] with a visible marker, and
/// refused over that on load.
#[derive(Clone, Debug, Serialize)]
pub struct OutsideText(Untrusted<String>);

impl OutsideText {
    pub fn new(text: &str) -> Self {
        Self(Untrusted::new(cap_text(text, MAX_OUTSIDE_TEXT_BYTES)))
    }

    /// The text, still untrusted.
    pub fn untrusted(&self) -> &Untrusted<String> {
        &self.0
    }
}

impl<'de> Deserialize<'de> for OutsideText {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let inner = Untrusted::<String>::deserialize(deserializer)?;
        if inner.byte_len() > MAX_OUTSIDE_TEXT_BYTES {
            return Err(serde::de::Error::custom("outside text over 1 KiB"));
        }
        Ok(Self(inner))
    }
}

impl Unknown {
    /// The detail text, if any. Still untrusted.
    pub fn detail(&self) -> Option<&Untrusted<String>> {
        self.detail.as_ref()
    }

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
    /// Something answered that might be this product but was not identified.
    Unidentified,
}

/// What a service, host or setup is, and how sure the sensor was.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[non_exhaustive]
#[serde(deny_unknown_fields)]
pub enum Claim {
    Host {
        os: OutsideText,
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
        /// Catalog products whose recognised ports include this endpoint's port:
        /// what it might be. Their absence can no longer be claimed.
        candidates: Vec<CatalogId>,
        version_label: Option<OutsideText>,
        source_label: Option<OutsideText>,
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

/// Proof that a search was complete. Built only by `Presence::absent` and
/// `ServiceState::not_found`, with the evidence of what was searched; a value
/// read from JSON is refused unless it says `Complete`. Any two complete
/// searches compare equal (the evidence is for people, not for folding).
#[derive(Clone, Debug, Serialize)]
pub struct CompleteSearch {
    coverage: Coverage,
    evidence: Evidence,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct CompleteSearchWire {
    coverage: Coverage,
    evidence: Evidence,
}

impl<'de> Deserialize<'de> for CompleteSearch {
    fn deserialize<D: serde::Deserializer<'de>>(deserializer: D) -> Result<Self, D::Error> {
        let wire = CompleteSearchWire::deserialize(deserializer)?;
        match wire.coverage {
            Coverage::Complete => Ok(Self {
                coverage: wire.coverage,
                evidence: wire.evidence,
            }),
            Coverage::Partial => Err(serde::de::Error::custom("absence needs a complete search")),
        }
    }
}

impl CompleteSearch {
    /// What was searched, and what came back.
    pub fn evidence(&self) -> &Evidence {
        &self.evidence
    }
}

impl PartialEq for CompleteSearch {
    fn eq(&self, _: &Self) -> bool {
        true
    }
}

impl Eq for CompleteSearch {}

/// Whether a package is there. `Absent` is a claim, never a gap: it carries a
/// [`CompleteSearch`], which only `Presence::absent` makes, so "not there"
/// can't exist without evidence of a complete search. Judge B's
/// `version = "none"` is `Seen(Absent)`; a package nobody looked for is `Unknown`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum Presence {
    Present,
    Absent(CompleteSearch),
}

impl Presence {
    /// "Looked and it is not there": `Seen(Absent)` for a complete search (with
    /// its evidence), `Unknown(IncompleteCoverage)` for anything less.
    pub fn absent(coverage: Coverage, search: Evidence) -> Observed<Presence> {
        match coverage {
            Coverage::Complete => Observed::Seen(Presence::Absent(CompleteSearch {
                coverage,
                evidence: search,
            })),
            Coverage::Partial => Observed::Unknown(Unknown::new(UnknownReason::IncompleteCoverage)),
        }
    }
}

/// What a service is doing. A stopped container is `Stopped`, never "running
/// because a fact exists"; `NotFound` carries a [`CompleteSearch`] and is built
/// only by `ServiceState::not_found`.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
pub enum ServiceState {
    Running,
    Stopped,
    NotFound(CompleteSearch),
}

impl ServiceState {
    /// `Seen(NotFound)` for a complete search, `Unknown(IncompleteCoverage)` otherwise.
    pub fn not_found(coverage: Coverage, search: Evidence) -> Observed<ServiceState> {
        match coverage {
            Coverage::Complete => Observed::Seen(ServiceState::NotFound(CompleteSearch {
                coverage,
                evidence: search,
            })),
            Coverage::Partial => Observed::Unknown(Unknown::new(UnknownReason::IncompleteCoverage)),
        }
    }
}

/// A package as the view reports it: proved absent, or installed (with a
/// version that may still be unknown).
#[derive(Clone, Debug, Serialize, Deserialize)]
pub enum PackageState {
    NotInstalled,
    Installed(Observed<PlainVersion>),
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
    Other(OutsideText),
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
    Other(OutsideText),
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

#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
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
    /// Containers and images (is the container runtime readable at all?).
    Containers,
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub enum BlindSpotKind {
    /// The sensor never ran or was never asked (for example, containers not checked).
    NotChecked,
    NoPermission,
    NoReply,
    Unparsable,
    TooBig,
    StoredByNewerGuardDog,
    HistorySetAside,
    /// Two detection methods gave different versions; the better one was used.
    MethodsDisagree,
    /// A better detection method gave no answer; a weaker one was used.
    BetterMethodUnavailable,
    /// A claim about a service or package whose subject was not a service.
    WrongSubject,
}

#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub enum RunsAs {
    Container {
        name: OutsideText,
        image: OutsideText,
        digest: Option<ImageDigest>,
    },
    Unit {
        name: OutsideText,
    },
    Binary {
        path: OutsideText,
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
#[serde(deny_unknown_fields)]
pub enum Backend {
    Live,
    Recorded { setup: SetupId },
    Fixture { setup: SetupId },
    Fake,
}

#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
#[serde(deny_unknown_fields)]
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
/// [`MAX_EVIDENCE`] pieces of evidence, dedupes candidates, and refuses more than
/// [`MAX_CANDIDATES`] of them, so a fact that can be built can be read back.
#[derive(Clone, Debug, Serialize, Deserialize)]
#[serde(try_from = "FactWire")]
pub struct Fact {
    pub subject: Subject,
    pub claim: Claim,
    pub source: Source,
    pub observed_at: Timestamp,
    evidence: Vec<Evidence>,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct FactWire {
    subject: Subject,
    claim: Claim,
    source: Source,
    observed_at: Timestamp,
    evidence: Vec<Evidence>,
}

impl TryFrom<FactWire> for Fact {
    type Error = FactError;
    fn try_from(wire: FactWire) -> Result<Self, FactError> {
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
    /// Builds a fact. An `Err` means the claim could not be recorded (today: an
    /// unrecognised endpoint with more than [`MAX_CANDIDATES`] candidates). A
    /// sensor must then emit a `BlindSpot` fact, never skip the fact: use
    /// [`Fact::new_or_blind_spot`].
    pub fn new(
        subject: Subject,
        mut claim: Claim,
        source: Source,
        observed_at: Timestamp,
        mut evidence: Vec<Evidence>,
    ) -> Result<Self, FactError> {
        evidence.truncate(MAX_EVIDENCE);
        if let Claim::Unrecognized { candidates, .. } = &mut claim {
            candidates.sort();
            candidates.dedup();
            if candidates.len() > MAX_CANDIDATES {
                return Err(FactError {
                    what: "candidates list (over 32 products)",
                });
            }
        }
        Ok(Self {
            subject,
            claim,
            source,
            observed_at,
            evidence,
        })
    }

    /// Like [`Fact::new`], but a claim that cannot be recorded becomes a
    /// `BlindSpot` on the same subject saying so, so the gap is never silent.
    pub fn new_or_blind_spot(
        subject: Subject,
        claim: Claim,
        source: Source,
        observed_at: Timestamp,
        evidence: Vec<Evidence>,
    ) -> Fact {
        match Fact::new(
            subject.clone(),
            claim,
            source.clone(),
            observed_at,
            evidence,
        ) {
            Ok(fact) => fact,
            Err(_) => Fact {
                subject,
                claim: Claim::BlindSpot {
                    area: Area::Services,
                    what: BlindSpotKind::TooBig,
                    // A literal that always parses; the fallback keeps this total.
                    hint: HintId::parse("unidentified-service-not-recorded")
                        .unwrap_or_else(|_| HintId(String::from("not-recorded"))),
                },
                source,
                observed_at,
                evidence: Vec::new(),
            },
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
