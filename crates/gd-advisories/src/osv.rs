//! OSV 1.9.2 records as bounded typed data.
//!
//! [`parse_advisory`] reads one record from bytes and does nothing else: no
//! network, no files, no clock, no subprocess. Links in a record are kept as
//! text and never followed.
//!
//! What it promises:
//! - Every size is bounded (the `MAX_*` constants). Going over a bound is a
//!   named [`OsvError`]; the record is never cut short into a "successful" one.
//! - Duplicate JSON keys and over-deep nesting are refused while reading, so
//!   hostile input cannot blow the stack or say two things at once.
//! - Text that came from outside stays [`Untrusted`]. Only values this module
//!   validates itself (the id, timestamps, package keys, enums) are plain.
//! - Nothing is dropped silently. A field it does not understand is kept as
//!   data (name and value, in its [`Gap`]) and listed there, in a stable order.
//!   The whole `database_specific` block is kept too. Past [`MAX_GAPS`] the
//!   record is still kept, with one final `GapsTruncated`.
//! - Only fields that decide matching refuse a record (id, modified, withdrawn,
//!   the affected packages, ranges, events and versions). Everything else is
//!   best effort: a bad value is left out and listed as an `UnreadableField` gap.
//! - Guard Dog's own fields (`guard_dog` curation, playbooks, scope notes) are
//!   read only for [`Source::GuardDogCorpus`] records. Matching code must treat a
//!   [`Gap`] as "I do not know", never as "this does not apply".
//! - It does not judge versions: bounds stay as the original strings.

use std::cell::RefCell;
use std::fmt;

use gd_core::Untrusted;
use serde::de::{self, DeserializeSeed, MapAccess, SeqAccess, Visitor};
use serde_json::{Map, Value};

use crate::package::{PackageError, PackageKey, canonical_package};

/// The most bytes one record may have.
pub const MAX_RECORD_BYTES: usize = 1 << 20;
/// The deepest JSON nesting accepted (the record itself is depth 1).
pub const MAX_DEPTH: usize = 64;
/// The most `affected` entries in one record.
pub const MAX_AFFECTED: usize = 256;
/// The most ranges and range events, together, in one record.
pub const MAX_RANGES_AND_EVENTS: usize = 1024;
/// The most listed versions, across all entries of one record.
pub const MAX_VERSIONS: usize = 10_000;
/// The longest version string, in bytes.
pub const MAX_VERSION_BYTES: usize = 256;
/// The most gaps of the non-matching kinds one record records (see
/// [`GapKind::decides_matching`]; those are never dropped).
pub const MAX_GAPS: usize = 256;

const MAX_ID_BYTES: usize = 128;
const MAX_SUMMARY_BYTES: usize = 4096;
const MAX_DETAILS_BYTES: usize = 128 * 1024;
const MAX_LIST: usize = 256;
const MAX_SEVERITIES: usize = 16;
const MAX_URL_BYTES: usize = 2048;
const MAX_SCORE_BYTES: usize = 512;
const MAX_ECOSYSTEM_BYTES: usize = 64;
const MAX_PURL_BYTES: usize = 512;
const MAX_NOTE_BYTES: usize = 4096;
const MAX_PLAYBOOK_STEPS: usize = 16;

type Object = Map<String, Value>;

/// Why a record was refused. It never quotes outside text raw.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum OsvError {
    /// The record is over [`MAX_RECORD_BYTES`].
    RecordTooLarge {
        /// Its size in bytes.
        bytes: usize,
    },
    /// Not valid JSON (or not UTF-8). The parser's message, as outside text.
    NotJson(Untrusted<String>),
    /// Valid JSON followed by more bytes.
    TrailingData,
    /// An object with the same key twice.
    DuplicateKey(Untrusted<String>),
    /// Nested deeper than [`MAX_DEPTH`].
    TooDeep,
    /// The top level is not a JSON object.
    NotAnObject,
    /// A required field is missing.
    MissingField(&'static str),
    /// A field has the wrong JSON type.
    WrongType(&'static str),
    /// The `id` is not a safe identifier.
    BadId,
    /// A timestamp is not `YYYY-MM-DDTHH:MM:SS[.fraction]Z`.
    BadTimestamp(&'static str),
    /// A string field is longer than its limit.
    TooLong(&'static str),
    /// A list (or the gap list) is longer than its limit.
    TooMany(&'static str),
    /// A range event is not exactly one `introduced`, `fixed`, `last_affected`
    /// or `limit` with a string value.
    BadEvent,
}

impl OsvError {
    /// A stable short code for logs and tests.
    pub fn code(&self) -> &'static str {
        match self {
            Self::RecordTooLarge { .. } => "record_too_large",
            Self::NotJson(_) => "not_json",
            Self::TrailingData => "trailing_data",
            Self::DuplicateKey(_) => "duplicate_key",
            Self::TooDeep => "too_deep",
            Self::NotAnObject => "not_an_object",
            Self::MissingField(_) => "missing_field",
            Self::WrongType(_) => "wrong_type",
            Self::BadId => "bad_id",
            Self::BadTimestamp(_) => "bad_timestamp",
            Self::TooLong(_) => "too_long",
            Self::TooMany(_) => "too_many",
            Self::BadEvent => "bad_event",
        }
    }
}

impl fmt::Display for OsvError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", self.code())?;
        match self {
            Self::RecordTooLarge { bytes } => {
                write!(f, ": {bytes} bytes, limit {MAX_RECORD_BYTES}")
            }
            Self::NotJson(why) => write!(f, ": {}", why.escape_for_terminal()),
            Self::DuplicateKey(key) => write!(f, ": {}", key.escape_for_terminal()),
            Self::MissingField(field)
            | Self::WrongType(field)
            | Self::BadTimestamp(field)
            | Self::TooLong(field)
            | Self::TooMany(field) => write!(f, ": {field}"),
            _ => Ok(()),
        }
    }
}

impl std::error::Error for OsvError {}

/// An advisory id such as `CVE-2024-3094` or `x_cln-2026-v26.06.8-...`:
/// 1 to 128 ASCII letters, digits, `_`, `.` or `-`, starting with a letter,
/// digit or `_`. Safe to print and to use as a file name.
#[derive(Clone, Debug, PartialEq, Eq, Hash, PartialOrd, Ord)]
pub struct AdvisoryId(String);

impl AdvisoryId {
    fn parse(s: &str) -> Result<Self, OsvError> {
        let ok = !s.is_empty()
            && s.len() <= MAX_ID_BYTES
            && s.starts_with(|c: char| c.is_ascii_alphanumeric() || c == '_')
            && s.chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '_' | '.' | '-'));
        if ok {
            Ok(Self(s.to_string()))
        } else {
            Err(OsvError::BadId)
        }
    }

    /// The id as text.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

/// A validated OSV timestamp, `YYYY-MM-DDTHH:MM:SS[.fraction]Z` (or `+00:00`
/// for the zone), kept as written.
#[derive(Clone, Debug, PartialEq, Eq, Hash)]
pub struct Timestamp(String);

impl Timestamp {
    fn parse(s: &str, field: &'static str) -> Result<Self, OsvError> {
        valid_timestamp(s)
            .then(|| Self(s.to_string()))
            .ok_or(OsvError::BadTimestamp(field))
    }

    /// The timestamp as written in the record.
    pub fn as_str(&self) -> &str {
        &self.0
    }
}

fn valid_timestamp(s: &str) -> bool {
    let Some(body) = s.strip_suffix('Z').or_else(|| s.strip_suffix("+00:00")) else {
        return false;
    };
    let (main, fraction) = match body.split_once('.') {
        Some((main, fraction)) => (main, Some(fraction)),
        None => (body, None),
    };
    if let Some(f) = fraction
        && (f.is_empty() || f.len() > 64 || !f.bytes().all(|b| b.is_ascii_digit()))
    {
        return false;
    }
    let digits = |part: &str, len: usize| -> Option<u32> {
        (part.len() == len && part.bytes().all(|b| b.is_ascii_digit()))
            .then(|| part.parse().ok())
            .flatten()
    };
    let Some((date, time)) = main.split_once('T') else {
        return false;
    };
    let mut d = date.split('-');
    let mut t = time.split(':');
    let (Some(y), Some(mo), Some(da), None) = (d.next(), d.next(), d.next(), d.next()) else {
        return false;
    };
    let (Some(h), Some(mi), Some(se), None) = (t.next(), t.next(), t.next(), t.next()) else {
        return false;
    };
    let (Some(y), Some(mo), Some(da)) = (digits(y, 4), digits(mo, 2), digits(da, 2)) else {
        return false;
    };
    let (Some(h), Some(mi), Some(se)) = (digits(h, 2), digits(mi, 2), digits(se, 2)) else {
        return false;
    };
    let leap = y % 4 == 0 && (y % 100 != 0 || y % 400 == 0);
    let days = match mo {
        1 | 3 | 5 | 7 | 8 | 10 | 12 => 31,
        4 | 6 | 9 | 11 => 30,
        2 if leap => 29,
        2 => 28,
        _ => return false,
    };
    (1..=days).contains(&da) && h < 24 && mi < 60 && se <= 60
}

/// What kind of severity score a record carries.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum SeverityKind {
    /// `CVSS_V2`
    CvssV2,
    /// `CVSS_V3`
    CvssV3,
    /// `CVSS_V4`
    CvssV4,
    /// `Ubuntu`
    Ubuntu,
    /// Any other type, as written.
    Other(Untrusted<String>),
}

/// One severity score, as the record gives it.
#[derive(Clone, Debug)]
pub struct Severity {
    /// The kind of score.
    pub kind: SeverityKind,
    /// The score text (a CVSS vector, for example), unparsed.
    pub score: Untrusted<String>,
    /// Who assigned it (`NVD`, `CNA`, `SELF`), when stated.
    pub source: Option<Untrusted<String>>,
}

/// What a reference link is for.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum ReferenceKind {
    /// `ADVISORY`
    Advisory,
    /// `ARTICLE`
    Article,
    /// `DETECTION`
    Detection,
    /// `DISCUSSION`
    Discussion,
    /// `REPORT`
    Report,
    /// `FIX`
    Fix,
    /// `INTRODUCED`
    Introduced,
    /// `GIT`
    Git,
    /// `PACKAGE`
    Package,
    /// `EVIDENCE`
    Evidence,
    /// `WEB`
    Web,
    /// Any other type, as written.
    Other(Untrusted<String>),
}

/// A link. It is text to show, never an instruction to fetch.
#[derive(Clone, Debug)]
pub struct Reference {
    /// What the link is for.
    pub kind: ReferenceKind,
    /// The address, unchecked.
    pub url: Untrusted<String>,
}

/// How a range's bounds are meant to be ordered, as the record declares.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum RangeKind {
    /// `SEMVER`
    Semver,
    /// `ECOSYSTEM`
    Ecosystem,
    /// `GIT` (commit hashes; ordering needs a commit graph).
    Git,
    /// A type this version does not know. The range stays in the data.
    Unsupported(Untrusted<String>),
}

/// One range event. The value is the original string.
#[derive(Clone, Debug)]
#[non_exhaustive]
pub enum Event {
    /// First affected version (`"0"` means "from the start").
    Introduced(Untrusted<String>),
    /// First fixed version.
    Fixed(Untrusted<String>),
    /// Last affected version.
    LastAffected(Untrusted<String>),
    /// An upper limit on the range.
    Limit(Untrusted<String>),
    /// An event kind this version does not know. It keeps its place in the
    /// list, so whoever evaluates the range can refuse to guess.
    Unrecognised,
}

/// One range of versions.
#[derive(Clone, Debug)]
pub struct Range {
    /// The declared ordering.
    pub kind: RangeKind,
    /// The repository a GIT range is about, unchecked.
    pub repo: Option<Untrusted<String>>,
    /// The events, in the order written.
    pub events: Vec<Event>,
    /// The range's own `database_specific`, kept whole. It never changes membership.
    pub extensions: Untrusted<Object>,
}

/// A package as the record names it, and its canonical key.
#[derive(Clone, Debug)]
pub struct Package {
    /// The ecosystem as written.
    pub ecosystem: Untrusted<String>,
    /// The name as written.
    pub name: Untrusted<String>,
    /// The package URL, when given, unchecked.
    pub purl: Option<Untrusted<String>>,
    /// The canonical identity, or why there is none. A missing key is a gap,
    /// not proof that the package is absent.
    pub key: Result<PackageKey, PackageError>,
}

/// Where an entry applies, from the reviewed `platform` and `model` fields.
/// `None` means the record says nothing, not "everywhere".
#[derive(Clone, Debug, Default)]
pub struct Scope {
    /// The `platform` note, such as an architecture condition, unparsed.
    pub platform: Option<Untrusted<String>>,
    /// The hardware `model` note, unparsed.
    pub model: Option<Untrusted<String>>,
}

/// One `affected` entry.
#[derive(Clone, Debug)]
pub struct AffectedEntry {
    /// The package.
    pub package: Package,
    /// Severity given for this entry alone.
    pub severity: Vec<Severity>,
    /// The ranges, in the order written.
    pub ranges: Vec<Range>,
    /// Exactly listed versions, original strings.
    pub versions: Vec<Untrusted<String>>,
    /// `ecosystem_specific`, kept whole.
    pub ecosystem_specific: Option<Untrusted<Value>>,
    /// Platform and model scope.
    pub scope: Scope,
    /// The entry's `database_specific`, kept whole (range notes and so on are
    /// prose and never override the events).
    pub extensions: Untrusted<Object>,
}

/// Guard Dog's own curation, from `database_specific.guard_dog` and its
/// neighbours. Fields the record leaves out stay empty.
#[derive(Clone, Debug, Default)]
pub struct Curation {
    /// The "what to do" steps, in order.
    pub playbook: Vec<Untrusted<String>>,
    /// The extra conditions, kept whole: Phase 2.2 owns their meaning.
    pub conditions: Option<Untrusted<Value>>,
    /// The note about the conditions' format.
    pub conditions_format: Option<Untrusted<String>>,
    /// The day the primary source was last read.
    pub source_checked: Option<Untrusted<String>>,
    /// What kind of primary source the record was written from.
    pub primary_source_kind: Option<Untrusted<String>>,
    /// Whether the vendor withheld the details (`true` only when stated).
    pub details_withheld_by_vendor: Option<bool>,
}

/// What kind of thing was not understood.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum GapKind {
    /// A field outside `database_specific` that this version does not know.
    UnknownField,
    /// A `database_specific` or `ecosystem_specific` key nobody has reviewed.
    /// Its data is kept; it is not interpreted.
    UnreviewedExtension,
    /// A reviewed field with the wrong type or size, so it was not read.
    UnreadableField,
    /// A range type this version does not know.
    UnknownRangeType,
    /// A range event kind this version does not know.
    UnknownEventKind,
    /// A package name that has no canonical key (the reason is inside).
    PackageIdentity(PackageError),
    /// An entry with neither a usable range nor a listed version.
    NoRangeOrVersions,
    /// A range with no events.
    EmptyRange,
    /// A record with no `affected` entries.
    NoAffectedEntries,
    /// A `schema_version` other than 1.9.2.
    UnexpectedSchemaVersion,
    /// More gaps than [`MAX_GAPS`]: later ones were not recorded. Treat the
    /// whole record as uncertain.
    GapsTruncated,
    /// A range with no `introduced` event. Under OSV's rules it matches
    /// nothing, so it must read as unknown, never as "out of range".
    RangeWithoutIntroduced,
    /// A range with both a `fixed` and a `last_affected` event.
    FixedAndLastAffected,
}

impl GapKind {
    /// Whether this gap bears on whether the record matches (so it is never
    /// dropped when there are too many gaps): unknown range types and event
    /// kinds, ranges that cannot be read as written, and packages and entries
    /// that cannot be identified or evaluated.
    pub fn decides_matching(self) -> bool {
        matches!(
            self,
            Self::RangeWithoutIntroduced
                | Self::FixedAndLastAffected
                | Self::UnknownRangeType
                | Self::UnknownEventKind
                | Self::PackageIdentity(_)
                | Self::NoRangeOrVersions
                | Self::EmptyRange
        )
    }

    /// A stable short code for logs and tests.
    pub fn code(self) -> &'static str {
        match self {
            Self::UnknownField => "unknown_field",
            Self::UnreviewedExtension => "unreviewed_extension",
            Self::UnreadableField => "unreadable_field",
            Self::UnknownRangeType => "unknown_range_type",
            Self::UnknownEventKind => "unknown_event_kind",
            Self::PackageIdentity(_) => "package_identity",
            Self::NoRangeOrVersions => "no_range_or_versions",
            Self::EmptyRange => "empty_range",
            Self::NoAffectedEntries => "no_affected_entries",
            Self::UnexpectedSchemaVersion => "unexpected_schema_version",
            Self::GapsTruncated => "gaps_truncated",
            Self::RangeWithoutIntroduced => "range_without_introduced",
            Self::FixedAndLastAffected => "fixed_and_last_affected",
        }
    }
}

/// Something in a record that was kept but not understood.
#[derive(Clone, Debug)]
pub struct Gap {
    /// What kind of gap.
    pub kind: GapKind,
    /// Where, as a path built from fixed names and positions, such as
    /// `affected[2].ranges[0]`. Empty for the top level.
    pub at: String,
    /// The outside name involved (an unknown key or type), if any.
    pub name: Option<Untrusted<String>>,
    /// The outside value involved (an unknown field's value), kept as data.
    pub value: Option<Untrusted<Value>>,
}

/// Where a record came from, which decides how far its Guard Dog fields are trusted.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum Source {
    /// Guard Dog's own reviewed corpus (`advisories/`). Its `guard_dog`
    /// curation, scope notes and playbooks are read.
    GuardDogCorpus,
    /// Anything else (OSV.dev, GHSA, a mirror). `guard_dog`, scope and other
    /// `database_specific` keys stay data with a gap; nothing from them
    /// can speak with Guard Dog's voice.
    External,
}

/// A refused record, with what is known about it so the caller can still raise
/// a "possibly affected" question against the right product.
#[derive(Clone, Debug)]
pub struct Refusal {
    /// Why it was refused.
    pub error: OsvError,
    /// The record's id, when it was readable.
    pub id: Option<AdvisoryId>,
    /// The packages whose names could be put in canonical form.
    pub packages: Vec<PackageKey>,
    /// Whether `packages` is every package in the record. When false, some
    /// package could not be read, so a caller must not assume the others are
    /// the only ones affected.
    pub packages_complete: bool,
}

impl fmt::Display for Refusal {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match &self.id {
            Some(id) => write!(f, "{} ({})", self.error, id.as_str()),
            None => self.error.fmt(f),
        }
    }
}

impl std::error::Error for Refusal {}

/// One OSV record, typed.
#[derive(Clone, Debug)]
pub struct Advisory {
    /// The record's id.
    pub id: AdvisoryId,
    /// The `schema_version` as written, if any.
    pub schema_version: Option<Untrusted<String>>,
    /// When the record was last modified.
    pub modified: Timestamp,
    /// When it was published.
    pub published: Option<Timestamp>,
    /// When the source withdrew it. A withdrawal is dated history, not a fix.
    pub withdrawn: Option<Timestamp>,
    /// Other ids for the same issue.
    pub aliases: Vec<Untrusted<String>>,
    /// Related ids.
    pub related: Vec<Untrusted<String>>,
    /// Upstream ids.
    pub upstream: Vec<Untrusted<String>>,
    /// The one-line summary.
    pub summary: Option<Untrusted<String>>,
    /// The longer description.
    pub details: Option<Untrusted<String>>,
    /// Severity scores for the whole record.
    pub severity: Vec<Severity>,
    /// The affected packages and versions, in the order written.
    pub affected: Vec<AffectedEntry>,
    /// Links.
    pub references: Vec<Reference>,
    /// `credits`, kept whole.
    pub credits: Option<Untrusted<Value>>,
    /// Guard Dog's curation.
    pub curation: Curation,
    /// The record's whole `database_specific`, kept as data.
    pub extensions: Untrusted<Object>,
    /// Everything kept but not understood, in a stable order.
    pub gaps: Vec<Gap>,
}

impl Advisory {
    /// Whether the source has withdrawn this record.
    pub fn is_withdrawn(&self) -> bool {
        self.withdrawn.is_some()
    }
}

/// Reads one OSV record of unknown origin ([`Source::External`]), returning
/// only the bare error. Feed code must use [`parse_advisory_from`], whose
/// refusal carries the id and packages so the refusal can be raised against the
/// right product. See the module documentation for the guarantees.
pub fn parse_advisory(bytes: &[u8]) -> Result<Advisory, OsvError> {
    parse_advisory_from(bytes, Source::External).map_err(|refusal| refusal.error)
}

/// Reads one OSV record from a stated source. A refusal carries the record's
/// id and package keys when they could be read.
pub fn parse_advisory_from(bytes: &[u8], source: Source) -> Result<Advisory, Refusal> {
    let bare = |error| Refusal {
        error,
        id: None,
        packages: Vec::new(),
        packages_complete: false,
    };
    let value = read_json(bytes).map_err(bare)?;
    let top = value
        .as_object()
        .ok_or(OsvError::NotAnObject)
        .map_err(bare)?;
    Reader::new(source).advisory(top).map_err(|error| {
        let (packages, packages_complete) = scan_packages(top);
        Refusal {
            error,
            id: present(top, "id")
                .and_then(Value::as_str)
                .and_then(|s| AdvisoryId::parse(s).ok()),
            packages,
            packages_complete,
        }
    })
}

/// The canonical keys of every package that can be read, without failing, and
/// whether that was every package (false when `affected` is not a list, or any
/// entry's package could not be read). The record is at most 1 MiB, so scanning
/// all entries is bounded.
fn scan_packages(top: &Object) -> (Vec<PackageKey>, bool) {
    let mut complete = true;
    let mut keys = Vec::new();
    match present(top, "affected") {
        None => {}
        Some(Value::Array(entries)) => {
            for entry in entries {
                let key = entry.get("package").and_then(|p| {
                    canonical_package(p.get("ecosystem")?.as_str()?, p.get("name")?.as_str()?).ok()
                });
                match key {
                    Some(key) => keys.push(key),
                    None => complete = false,
                }
            }
        }
        Some(_) => complete = false,
    }
    keys.sort();
    keys.dedup();
    (keys, complete)
}

// ------------------------------------------------------------ strict JSON

/// Reads JSON into a `Value`, refusing duplicate keys and nesting over
/// [`MAX_DEPTH`] while it goes, so neither can reach later code.
fn read_json(bytes: &[u8]) -> Result<Value, OsvError> {
    if bytes.len() > MAX_RECORD_BYTES {
        return Err(OsvError::RecordTooLarge { bytes: bytes.len() });
    }
    let failure = RefCell::new(None);
    let mut de = serde_json::Deserializer::from_slice(bytes);
    let seed = Strict {
        depth: 0,
        failure: &failure,
    };
    let read = seed.deserialize(&mut de).and_then(|v| de.end().map(|()| v));
    match read {
        Ok(value) => Ok(value),
        Err(e) => Err(failure.take().unwrap_or_else(|| {
            if e.to_string().starts_with("trailing characters") {
                OsvError::TrailingData
            } else {
                OsvError::NotJson(Untrusted::new(e.to_string()))
            }
        })),
    }
}

struct Strict<'a> {
    depth: usize,
    failure: &'a RefCell<Option<OsvError>>,
}

impl Strict<'_> {
    fn fail<E: de::Error>(&self, error: OsvError) -> E {
        let message = error.code();
        *self.failure.borrow_mut() = Some(error);
        E::custom(message)
    }

    fn child(&self) -> Strict<'_> {
        Strict {
            depth: self.depth.saturating_add(1),
            failure: self.failure,
        }
    }
}

impl<'de> DeserializeSeed<'de> for Strict<'_> {
    type Value = Value;

    fn deserialize<D: serde::Deserializer<'de>>(self, d: D) -> Result<Value, D::Error> {
        d.deserialize_any(self)
    }
}

impl<'de> Visitor<'de> for Strict<'_> {
    type Value = Value;

    fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str("any JSON value")
    }

    fn visit_bool<E: de::Error>(self, v: bool) -> Result<Value, E> {
        Ok(Value::Bool(v))
    }

    fn visit_i64<E: de::Error>(self, v: i64) -> Result<Value, E> {
        Ok(Value::from(v))
    }

    fn visit_u64<E: de::Error>(self, v: u64) -> Result<Value, E> {
        Ok(Value::from(v))
    }

    fn visit_f64<E: de::Error>(self, v: f64) -> Result<Value, E> {
        serde_json::Number::from_f64(v)
            .map(Value::Number)
            .ok_or_else(|| E::custom("number out of range"))
    }

    fn visit_str<E: de::Error>(self, v: &str) -> Result<Value, E> {
        Ok(Value::String(v.to_string()))
    }

    fn visit_string<E: de::Error>(self, v: String) -> Result<Value, E> {
        Ok(Value::String(v))
    }

    fn visit_unit<E: de::Error>(self) -> Result<Value, E> {
        Ok(Value::Null)
    }

    fn visit_seq<A: SeqAccess<'de>>(self, mut seq: A) -> Result<Value, A::Error> {
        if self.depth >= MAX_DEPTH {
            return Err(self.fail(OsvError::TooDeep));
        }
        let mut items = Vec::new();
        while let Some(item) = seq.next_element_seed(self.child())? {
            items.push(item);
        }
        Ok(Value::Array(items))
    }

    fn visit_map<A: MapAccess<'de>>(self, mut map: A) -> Result<Value, A::Error> {
        if self.depth >= MAX_DEPTH {
            return Err(self.fail(OsvError::TooDeep));
        }
        let mut object = Object::new();
        while let Some(key) = map.next_key::<String>()? {
            if object.contains_key(&key) {
                return Err(self.fail(OsvError::DuplicateKey(Untrusted::new(key))));
            }
            let value = map.next_value_seed(self.child())?;
            object.insert(key, value);
        }
        Ok(Value::Object(object))
    }
}

// -------------------------------------------------------- typed extraction
//
// Two tiers. Hard fields decide what a record matches (id, modified,
// withdrawn, and the affected packages, ranges, events and versions): when
// one is malformed or over budget, the record is refused. Everything else is
// read best effort: a bad or oversized value is left out and listed as an
// `UnreadableField` gap, so a cosmetic problem can never hide an advisory.

fn present<'a>(o: &'a Object, key: &str) -> Option<&'a Value> {
    o.get(key).filter(|v| !v.is_null())
}

fn string<'a>(v: &'a Value, field: &'static str, max: usize) -> Result<&'a str, OsvError> {
    let s = v.as_str().ok_or(OsvError::WrongType(field))?;
    if s.len() > max {
        Err(OsvError::TooLong(field))
    } else {
        Ok(s)
    }
}

fn required<'a>(
    o: &'a Object,
    key: &str,
    field: &'static str,
    max: usize,
) -> Result<&'a str, OsvError> {
    string(
        present(o, key).ok_or(OsvError::MissingField(field))?,
        field,
        max,
    )
}

fn optional<'a>(
    o: &'a Object,
    key: &str,
    field: &'static str,
    max: usize,
) -> Result<Option<&'a str>, OsvError> {
    present(o, key).map(|v| string(v, field, max)).transpose()
}

fn items<'a>(
    o: &'a Object,
    key: &str,
    field: &'static str,
    max: usize,
) -> Result<&'a [Value], OsvError> {
    let Some(v) = present(o, key) else {
        return Ok(&[]);
    };
    let list = v.as_array().ok_or(OsvError::WrongType(field))?;
    if list.len() > max {
        Err(OsvError::TooMany(field))
    } else {
        Ok(list)
    }
}

fn object<'a>(v: &'a Value, field: &'static str) -> Result<&'a Object, OsvError> {
    v.as_object().ok_or(OsvError::WrongType(field))
}

fn untrusted(s: &str) -> Untrusted<String> {
    Untrusted::new(s.to_string())
}

fn join(at: &str, name: &str) -> String {
    if at.is_empty() {
        name.to_string()
    } else {
        format!("{at}.{name}")
    }
}

/// Keys of `database_specific` that the curation guide documents. They are
/// kept as data; only the first few are typed. Read only for Guard Dog's corpus.
const REVIEWED_RECORD_EXTENSIONS: [&str; 16] = [
    "guard_dog",
    "primary_source_kind",
    "details_withheld_by_vendor",
    "no_cve",
    "vendor_severity",
    "vendor_severity_tier",
    "vendor_severity_counts",
    "published_basis",
    "base_layer_case",
    "exploited_in_the_wild",
    "not_in_osv_as_of",
    "cvss",
    "affected_party",
    "primary_source_note",
    "primary_source_retrieved",
    "updating_is_not_enough",
];
const REVIEWED_ENTRY_EXTENSIONS: [&str; 6] = [
    "platform",
    "model",
    "range_note",
    "fixed_in",
    "last_affected_stated",
    "base_layer_case",
];
const REVIEWED_GUARD_DOG: [&str; 4] = [
    "conditions",
    "conditions_format",
    "playbook",
    "source_checked",
];

struct Reader {
    source: Source,
    gaps: Vec<Gap>,
    truncated: bool,
    counted: usize,
    ranges_and_events: usize,
    versions: usize,
}

impl Reader {
    fn new(source: Source) -> Self {
        Self {
            source,
            gaps: Vec::new(),
            truncated: false,
            counted: 0,
            ranges_and_events: 0,
            versions: 0,
        }
    }

    fn corpus(&self) -> bool {
        self.source == Source::GuardDogCorpus
    }

    /// Records a gap. Gaps that decide matching (see [`GapKind::decides_matching`])
    /// are never dropped. Past [`MAX_GAPS`] of the other kinds it records one
    /// `GapsTruncated` and nothing more of them: the record is kept, and marked
    /// uncertain as a whole.
    fn gap(&mut self, kind: GapKind, at: &str, name: Option<&str>, value: Option<&Value>) {
        let relevant = kind.decides_matching();
        if !relevant {
            if self.truncated {
                return;
            }
            if self.counted >= MAX_GAPS {
                self.truncated = true;
                self.gaps.push(Gap {
                    kind: GapKind::GapsTruncated,
                    at: String::new(),
                    name: None,
                    value: None,
                });
                return;
            }
            self.counted += 1;
        }
        self.gaps.push(Gap {
            kind,
            at: at.to_string(),
            name: name.map(untrusted),
            value: value.map(|v| Untrusted::new(v.clone())),
        });
    }

    /// Unwraps a best-effort read, or records why the field was left out.
    fn soft<T>(&mut self, read: Result<T, OsvError>, at: &str, name: &str) -> Option<T> {
        match read {
            Ok(v) => Some(v),
            Err(_) => {
                self.gap(GapKind::UnreadableField, at, Some(name), None);
                None
            }
        }
    }

    /// One gap, with its value, for each key of `o` outside `known`, sorted.
    fn unknown_keys(&mut self, o: &Object, known: &[&str], kind: GapKind, at: &str) {
        let mut extra: Vec<&String> = o.keys().filter(|k| !known.contains(&k.as_str())).collect();
        extra.sort_unstable();
        for key in extra {
            self.gap(kind, at, Some(key), o.get(key.as_str()));
        }
    }

    /// An optional object field kept whole; a non-object is left out with a gap.
    fn soft_object(&mut self, o: &Object, key: &'static str, at: &str) -> Object {
        match present(o, key).map(|v| object(v, key)).transpose() {
            Ok(found) => found.cloned().unwrap_or_default(),
            Err(_) => {
                self.gap(GapKind::UnreadableField, at, Some(key), None);
                Object::new()
            }
        }
    }

    /// The items of an optional list, best effort: a list that is not a list is
    /// left out, and one over `max` is cut with a gap saying so.
    fn soft_list<'a>(
        &mut self,
        o: &'a Object,
        key: &'static str,
        at: &str,
        max: usize,
    ) -> &'a [Value] {
        let Some(v) = present(o, key) else {
            return &[];
        };
        let Some(list) = v.as_array() else {
            self.gap(GapKind::UnreadableField, at, Some(key), None);
            return &[];
        };
        if list.len() > max {
            self.gap(GapKind::UnreadableField, at, Some(key), None);
        }
        list.get(..max).unwrap_or(list)
    }

    fn soft_texts(&mut self, o: &Object, key: &'static str) -> Vec<Untrusted<String>> {
        let mut out = Vec::new();
        for (i, v) in self.soft_list(o, key, "", MAX_LIST).iter().enumerate() {
            let read = string(v, key, MAX_ID_BYTES * 2).map(untrusted);
            out.extend(self.soft(read, &format!("{key}[{i}]"), key));
        }
        out
    }

    fn count_ranges_and_events(&mut self, n: usize) -> Result<(), OsvError> {
        self.ranges_and_events = self.ranges_and_events.saturating_add(n);
        if self.ranges_and_events > MAX_RANGES_AND_EVENTS {
            return Err(OsvError::TooMany("ranges and events"));
        }
        Ok(())
    }

    fn advisory(mut self, top: &Object) -> Result<Advisory, OsvError> {
        const KNOWN: [&str; 15] = [
            "schema_version",
            "id",
            "modified",
            "published",
            "withdrawn",
            "aliases",
            "related",
            "upstream",
            "summary",
            "details",
            "severity",
            "affected",
            "references",
            "credits",
            "database_specific",
        ];
        // Hard fields.
        let id = AdvisoryId::parse(required(top, "id", "id", MAX_ID_BYTES + 1)?)?;
        let modified = Timestamp::parse(
            required(top, "modified", "modified", MAX_ID_BYTES)?,
            "modified",
        )?;
        let withdrawn = optional(top, "withdrawn", "withdrawn", MAX_ID_BYTES)?
            .map(|s| Timestamp::parse(s, "withdrawn"))
            .transpose()?;

        // Best-effort fields.
        let published = optional(top, "published", "published", MAX_ID_BYTES)
            .and_then(|s| s.map(|s| Timestamp::parse(s, "published")).transpose());
        let published = self.soft(published, "", "published").flatten();
        let schema_version = optional(top, "schema_version", "schema_version", MAX_ID_BYTES);
        let schema_version = self.soft(schema_version, "", "schema_version").flatten();
        let summary = optional(top, "summary", "summary", MAX_SUMMARY_BYTES);
        let summary = self.soft(summary, "", "summary").flatten().map(untrusted);
        let details = optional(top, "details", "details", MAX_DETAILS_BYTES);
        let details = self.soft(details, "", "details").flatten().map(untrusted);
        let aliases = self.soft_texts(top, "aliases");
        let related = self.soft_texts(top, "related");
        let upstream = self.soft_texts(top, "upstream");
        let severity = self.severities(top, "");
        let references = self.references(top);
        let credits = match present(top, "credits") {
            None => None,
            Some(v) if v.is_array() => Some(Untrusted::new(v.clone())),
            Some(_) => {
                self.gap(GapKind::UnreadableField, "", Some("credits"), None);
                None
            }
        };
        let db = self.soft_object(top, "database_specific", "");

        if schema_version.is_some_and(|v| v != "1.9.2") {
            self.gap(
                GapKind::UnexpectedSchemaVersion,
                "schema_version",
                None,
                None,
            );
        }
        self.unknown_keys(top, &KNOWN, GapKind::UnknownField, "");
        let reviewed: &[&str] = if self.corpus() {
            &REVIEWED_RECORD_EXTENSIONS
        } else {
            &[]
        };
        self.unknown_keys(
            &db,
            reviewed,
            GapKind::UnreviewedExtension,
            "database_specific",
        );
        let curation = if self.corpus() {
            self.curation(&db)
        } else {
            Curation::default()
        };

        let entries = items(top, "affected", "affected", MAX_AFFECTED)?;
        let mut affected = Vec::with_capacity(entries.len());
        for (i, entry) in entries.iter().enumerate() {
            affected.push(self.entry(entry, &format!("affected[{i}]"))?);
        }
        if affected.is_empty() {
            self.gap(GapKind::NoAffectedEntries, "affected", None, None);
        }
        Ok(Advisory {
            id,
            schema_version: schema_version.map(untrusted),
            modified,
            published,
            withdrawn,
            aliases,
            related,
            upstream,
            summary,
            details,
            severity,
            affected,
            references,
            credits,
            curation,
            extensions: Untrusted::new(db),
            gaps: self.gaps,
        })
    }

    fn severities(&mut self, o: &Object, at: &str) -> Vec<Severity> {
        let mut out = Vec::new();
        for (i, v) in self
            .soft_list(o, "severity", at, MAX_SEVERITIES)
            .iter()
            .enumerate()
        {
            let here = format!("{}[{i}]", join(at, "severity"));
            let read = object(v, "severity").and_then(|s| {
                let kind = match required(s, "type", "severity.type", 32)? {
                    "CVSS_V2" => SeverityKind::CvssV2,
                    "CVSS_V3" => SeverityKind::CvssV3,
                    "CVSS_V4" => SeverityKind::CvssV4,
                    "Ubuntu" => SeverityKind::Ubuntu,
                    other => SeverityKind::Other(untrusted(other)),
                };
                Ok((
                    s,
                    Severity {
                        kind,
                        score: untrusted(required(s, "score", "severity.score", MAX_SCORE_BYTES)?),
                        source: optional(s, "source", "severity.source", 32)?.map(untrusted),
                    },
                ))
            });
            if let Some((s, severity)) = self.soft(read, &here, "severity") {
                self.unknown_keys(
                    s,
                    &["type", "score", "source"],
                    GapKind::UnknownField,
                    &here,
                );
                out.push(severity);
            }
        }
        out
    }

    fn references(&mut self, o: &Object) -> Vec<Reference> {
        let mut out = Vec::new();
        for (i, v) in self
            .soft_list(o, "references", "", MAX_LIST)
            .iter()
            .enumerate()
        {
            let here = format!("references[{i}]");
            let read = object(v, "references").and_then(|r| {
                let kind = match required(r, "type", "references.type", 32)? {
                    "ADVISORY" => ReferenceKind::Advisory,
                    "ARTICLE" => ReferenceKind::Article,
                    "DETECTION" => ReferenceKind::Detection,
                    "DISCUSSION" => ReferenceKind::Discussion,
                    "REPORT" => ReferenceKind::Report,
                    "FIX" => ReferenceKind::Fix,
                    "INTRODUCED" => ReferenceKind::Introduced,
                    "GIT" => ReferenceKind::Git,
                    "PACKAGE" => ReferenceKind::Package,
                    "EVIDENCE" => ReferenceKind::Evidence,
                    "WEB" => ReferenceKind::Web,
                    other => ReferenceKind::Other(untrusted(other)),
                };
                let url = untrusted(required(r, "url", "references.url", MAX_URL_BYTES)?);
                Ok((r, Reference { kind, url }))
            });
            if let Some((r, reference)) = self.soft(read, &here, "references") {
                self.unknown_keys(r, &["type", "url"], GapKind::UnknownField, &here);
                out.push(reference);
            }
        }
        out
    }

    /// Reads Guard Dog's curation from `database_specific` (corpus records
    /// only), best effort: a field with the wrong shape becomes a gap, and the
    /// raw data is kept anyway.
    fn curation(&mut self, db: &Object) -> Curation {
        let mut c = Curation::default();
        let at = "database_specific";
        let kind = optional(
            db,
            "primary_source_kind",
            "primary_source_kind",
            MAX_NOTE_BYTES,
        );
        c.primary_source_kind = self
            .soft(kind, at, "primary_source_kind")
            .flatten()
            .map(untrusted);
        match present(db, "details_withheld_by_vendor").map(Value::as_bool) {
            None => {}
            Some(Some(flag)) => c.details_withheld_by_vendor = Some(flag),
            Some(None) => self.gap(
                GapKind::UnreadableField,
                at,
                Some("details_withheld_by_vendor"),
                None,
            ),
        }
        let Some(guard) = present(db, "guard_dog") else {
            return c;
        };
        let at = "database_specific.guard_dog";
        let Some(g) = guard.as_object() else {
            self.gap(
                GapKind::UnreadableField,
                "database_specific",
                Some("guard_dog"),
                None,
            );
            return c;
        };
        c.conditions = present(g, "conditions").map(|v| Untrusted::new(v.clone()));
        for (key, slot) in [
            ("conditions_format", &mut c.conditions_format),
            ("source_checked", &mut c.source_checked),
        ] {
            let read = optional(g, key, "guard_dog", MAX_NOTE_BYTES);
            *slot = self.soft(read, at, key).flatten().map(untrusted);
        }
        let steps = items(g, "playbook", "playbook", MAX_PLAYBOOK_STEPS).and_then(|steps| {
            steps
                .iter()
                .map(|v| string(v, "playbook", MAX_NOTE_BYTES).map(untrusted))
                .collect()
        });
        c.playbook = self.soft(steps, at, "playbook").unwrap_or_default();
        self.unknown_keys(g, &REVIEWED_GUARD_DOG, GapKind::UnreviewedExtension, at);
        c
    }

    fn entry(&mut self, value: &Value, at: &str) -> Result<AffectedEntry, OsvError> {
        const KNOWN: [&str; 6] = [
            "package",
            "severity",
            "ranges",
            "versions",
            "ecosystem_specific",
            "database_specific",
        ];
        let e = object(value, "affected")?;
        self.unknown_keys(e, &KNOWN, GapKind::UnknownField, at);
        let package = self.package(
            present(e, "package").ok_or(OsvError::MissingField("affected.package"))?,
            &format!("{at}.package"),
        )?;
        let severity = self.severities(e, at);
        let ecosystem_specific = present(e, "ecosystem_specific").map(|v| {
            if let Some(specific) = v.as_object() {
                let here = format!("{at}.ecosystem_specific");
                self.unknown_keys(specific, &[], GapKind::UnreviewedExtension, &here);
            } else {
                self.gap(
                    GapKind::UnreadableField,
                    at,
                    Some("ecosystem_specific"),
                    None,
                );
            }
            Untrusted::new(v.clone())
        });

        let range_list = items(e, "ranges", "affected.ranges", MAX_RANGES_AND_EVENTS)?;
        let mut ranges = Vec::with_capacity(range_list.len());
        for (j, range) in range_list.iter().enumerate() {
            ranges.push(self.range(range, &format!("{at}.ranges[{j}]"))?);
        }
        let version_list = items(e, "versions", "affected.versions", MAX_VERSIONS)?;
        self.versions = self.versions.saturating_add(version_list.len());
        if self.versions > MAX_VERSIONS {
            return Err(OsvError::TooMany("versions"));
        }
        let versions = version_list
            .iter()
            .map(|v| string(v, "affected.versions", MAX_VERSION_BYTES).map(untrusted))
            .collect::<Result<Vec<_>, _>>()?;
        if versions.is_empty() && ranges.iter().all(|r| r.events.is_empty()) {
            self.gap(GapKind::NoRangeOrVersions, at, None, None);
        }

        let db_at = format!("{at}.database_specific");
        let db = self.soft_object(e, "database_specific", at);
        let mut scope = Scope::default();
        let reviewed: &[&str] = if self.corpus() {
            for (key, slot) in [
                ("platform", &mut scope.platform),
                ("model", &mut scope.model),
            ] {
                let read = optional(&db, key, "affected.scope", MAX_NOTE_BYTES);
                *slot = self.soft(read, &db_at, key).flatten().map(untrusted);
            }
            &REVIEWED_ENTRY_EXTENSIONS
        } else {
            &[]
        };
        self.unknown_keys(&db, reviewed, GapKind::UnreviewedExtension, &db_at);
        Ok(AffectedEntry {
            package,
            severity,
            ranges,
            versions,
            ecosystem_specific,
            scope,
            extensions: Untrusted::new(db),
        })
    }

    fn package(&mut self, value: &Value, at: &str) -> Result<Package, OsvError> {
        let p = object(value, "affected.package")?;
        self.unknown_keys(p, &["ecosystem", "name", "purl"], GapKind::UnknownField, at);
        let ecosystem = required(p, "ecosystem", "package.ecosystem", MAX_ECOSYSTEM_BYTES)?;
        let name = required(p, "name", "package.name", crate::package::MAX_PACKAGE_NAME)?;
        let purl = optional(p, "purl", "package.purl", MAX_PURL_BYTES);
        let purl = self.soft(purl, at, "purl").flatten();
        let key = canonical_package(ecosystem, name);
        if let Err(why) = key {
            self.gap(GapKind::PackageIdentity(why), at, None, None);
        }
        Ok(Package {
            ecosystem: untrusted(ecosystem),
            name: untrusted(name),
            purl: purl.map(untrusted),
            key,
        })
    }

    fn range(&mut self, value: &Value, at: &str) -> Result<Range, OsvError> {
        let r = object(value, "affected.ranges")?;
        self.count_ranges_and_events(1)?;
        let kind = match required(r, "type", "range.type", 32)? {
            "SEMVER" => RangeKind::Semver,
            "ECOSYSTEM" => RangeKind::Ecosystem,
            "GIT" => RangeKind::Git,
            other => {
                self.gap(GapKind::UnknownRangeType, at, Some(other), None);
                RangeKind::Unsupported(untrusted(other))
            }
        };
        self.unknown_keys(
            r,
            &["type", "repo", "events", "database_specific"],
            GapKind::UnknownField,
            at,
        );
        let repo = optional(r, "repo", "range.repo", MAX_URL_BYTES);
        let repo = self.soft(repo, at, "repo").flatten().map(untrusted);
        let event_list = items(r, "events", "range.events", MAX_RANGES_AND_EVENTS)?;
        if present(r, "events").is_none() {
            return Err(OsvError::MissingField("range.events"));
        }
        self.count_ranges_and_events(event_list.len())?;
        let mut events = Vec::with_capacity(event_list.len());
        for (k, event) in event_list.iter().enumerate() {
            events.push(self.event(event, &format!("{at}.events[{k}]"))?);
        }
        let has = |f: fn(&Event) -> bool| events.iter().any(f);
        if events.is_empty() {
            self.gap(GapKind::EmptyRange, at, None, None);
        } else if !has(|e| matches!(e, Event::Introduced(_))) {
            self.gap(GapKind::RangeWithoutIntroduced, at, None, None);
        }
        if has(|e| matches!(e, Event::Fixed(_))) && has(|e| matches!(e, Event::LastAffected(_))) {
            self.gap(GapKind::FixedAndLastAffected, at, None, None);
        }
        let extensions = self.soft_object(r, "database_specific", at);
        Ok(Range {
            kind,
            repo,
            events,
            extensions: Untrusted::new(extensions),
        })
    }

    fn event(&mut self, value: &Value, at: &str) -> Result<Event, OsvError> {
        let o = value
            .as_object()
            .filter(|o| o.len() == 1)
            .ok_or(OsvError::BadEvent)?;
        let (key, v) = o.iter().next().ok_or(OsvError::BadEvent)?;
        let make: fn(Untrusted<String>) -> Event = match key.as_str() {
            "introduced" => Event::Introduced,
            "fixed" => Event::Fixed,
            "last_affected" => Event::LastAffected,
            "limit" => Event::Limit,
            other => {
                self.gap(GapKind::UnknownEventKind, at, Some(other), Some(v));
                return Ok(Event::Unrecognised);
            }
        };
        let text = v.as_str().ok_or(OsvError::BadEvent)?;
        if text.len() > MAX_VERSION_BYTES {
            return Err(OsvError::TooLong("event version"));
        }
        Ok(make(untrusted(text)))
    }
}
