//! SemVer 2.0 (strict) and the Go tag adapter (design 2.1, section 2).
//!
//! [`SemVer`] reads exactly `X.Y.Z[-prerelease][+metadata]` and nothing else.
//! [`GoTag`] is the same grammar after removing at most one lowercase `v`; it
//! is the declared adapter for Go module tags and for catalog values such as
//! LND's. Both produce [`SemVerVersion`], which keeps the original spelling.
//!
//! Numbers are never converted to machine integers: they are validated decimal
//! strings compared by length, then bytes, so no input can overflow.

use std::cmp::Ordering;
use std::fmt;

use super::num::{MAX_COMPONENTS, Num};
use super::{Candidate, VersionError, VersionScheme};
use crate::MAX_VERSION_BYTES;

/// Reads ASCII digits only, nonempty, with no leading zero.
pub(crate) fn parse_num(s: &str) -> Result<Num, VersionError> {
    Num::strict(s).ok_or(VersionError::Malformed)
}

/// Refuses over-long input before any other work.
pub(crate) fn check_length(raw: &str) -> Result<(), VersionError> {
    if raw.len() > MAX_VERSION_BYTES {
        Err(VersionError::TooLong)
    } else {
        Ok(())
    }
}

/// One prerelease identifier: numeric ones sort below text ones.
#[derive(Clone, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum PreId {
    Numeric(Num),
    Text(String),
}

fn identifier_chars(s: &str) -> bool {
    !s.is_empty() && s.bytes().all(|b| b.is_ascii_alphanumeric() || b == b'-')
}

/// A parsed SemVer version. Order is SemVer precedence (metadata ignored);
/// [`SemVerVersion::identity`] is the exact text, metadata included.
#[derive(Clone, Debug)]
pub struct SemVerVersion {
    major: Num,
    minor: Num,
    patch: Num,
    pre: Vec<PreId>,
    build: Vec<String>,
    raw: String,
}

impl SemVerVersion {
    /// The spelling it was read from, including any `v` the Go adapter removed.
    #[must_use]
    pub fn raw(&self) -> &str {
        &self.raw
    }

    /// The exact identity: the canonical text with metadata, without the `v`.
    #[must_use]
    pub fn identity(&self) -> String {
        self.to_string()
    }
}

impl fmt::Display for SemVerVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)?;
        for (i, id) in self.pre.iter().enumerate() {
            f.write_str(if i == 0 { "-" } else { "." })?;
            match id {
                PreId::Numeric(n) => write!(f, "{n}")?,
                PreId::Text(t) => f.write_str(t)?,
            }
        }
        for (i, id) in self.build.iter().enumerate() {
            f.write_str(if i == 0 { "+" } else { "." })?;
            f.write_str(id)?;
        }
        Ok(())
    }
}

impl Ord for SemVerVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        self.major
            .cmp(&other.major)
            .then_with(|| self.minor.cmp(&other.minor))
            .then_with(|| self.patch.cmp(&other.patch))
            .then_with(|| match (self.pre.is_empty(), other.pre.is_empty()) {
                (true, true) => Ordering::Equal,
                (true, false) => Ordering::Greater,
                (false, true) => Ordering::Less,
                (false, false) => self.pre.cmp(&other.pre),
            })
    }
}
impl PartialOrd for SemVerVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl PartialEq for SemVerVersion {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}
impl Eq for SemVerVersion {}

/// Reads strict SemVer from `text` and records `raw` as its spelling.
fn read(text: &str, raw: &str) -> Result<SemVerVersion, VersionError> {
    check_length(raw)?;
    let (head, build) = match text.split_once('+') {
        Some((h, b)) => (h, Some(b)),
        None => (text, None),
    };
    let (core, pre) = match head.split_once('-') {
        Some((c, p)) => (c, Some(p)),
        None => (head, None),
    };
    let mut parts = core.split('.');
    let (Some(a), Some(b), Some(c), None) =
        (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(VersionError::Malformed);
    };
    let (major, minor, patch) = (parse_num(a)?, parse_num(b)?, parse_num(c)?);

    let mut pre_ids = Vec::new();
    if let Some(p) = pre {
        for (i, id) in p.split('.').enumerate() {
            if i >= MAX_COMPONENTS {
                return Err(VersionError::TooLong);
            }
            if !identifier_chars(id) {
                return Err(VersionError::Malformed);
            }
            pre_ids.push(if id.bytes().all(|b| b.is_ascii_digit()) {
                PreId::Numeric(parse_num(id)?)
            } else {
                PreId::Text(id.to_string())
            });
        }
    }
    let mut build_ids = Vec::new();
    if let Some(m) = build {
        for (i, id) in m.split('.').enumerate() {
            if i >= MAX_COMPONENTS {
                return Err(VersionError::TooLong);
            }
            if !identifier_chars(id) {
                return Err(VersionError::Malformed);
            }
            build_ids.push(id.to_string());
        }
    }
    Ok(SemVerVersion {
        major,
        minor,
        patch,
        pre: pre_ids,
        build: build_ids,
        raw: raw.to_string(),
    })
}

/// Strict SemVer 2.0: no `v`, no guessing.
#[derive(Clone, Copy, Debug, Default)]
pub struct SemVer;

impl VersionScheme for SemVer {
    type Version = SemVerVersion;

    fn parse(&self, raw: &str) -> Result<SemVerVersion, VersionError> {
        read(raw, raw)
    }

    fn same_identity(&self, a: &str, b: &str) -> Option<bool> {
        let (a, b) = (self.parse(a).ok()?, self.parse(b).ok()?);
        Some(a.identity() == b.identity())
    }

    fn reads_semver_ranges(&self) -> bool {
        true
    }

    fn orders(&self) -> bool {
        true
    }
}

/// SemVer after the declared Go and catalog tag adapter: at most one lowercase
/// `v` is removed (`v0.5.1` is `0.5.1`), the raw spelling is kept, and an
/// incomplete tag such as `v1` or `v1.2` is refused. Go pseudo-versions stay
/// whole SemVer prereleases; their hashes are never compared as ancestry.
#[derive(Clone, Copy, Debug, Default)]
pub struct GoTag;

impl VersionScheme for GoTag {
    type Version = SemVerVersion;

    fn parse(&self, raw: &str) -> Result<SemVerVersion, VersionError> {
        read(raw.strip_prefix('v').unwrap_or(raw), raw)
    }

    /// An installed Go value carries no build metadata except Go's own
    /// `+incompatible`: a canonical Go module version has none, and any other
    /// (`+dirty`, `+build5`) says nothing about which code was built, so it is
    /// refused, never ordered as the clean tag.
    ///
    /// A git-describe value (`<tag>-<N>-g<hash>`, or a `-dirty` build) is not a
    /// release and must never be ordered as a SemVer prerelease (design 2.1
    /// section 2), so it is refused. (Advisory boundaries and listed versions go
    /// through `parse` and keep ordinary rules.)
    fn candidate(&self, raw: &str) -> Result<Candidate<SemVerVersion>, VersionError> {
        let v = self.parse(raw)?;
        if !v.build.is_empty() && v.build.as_slice() != ["incompatible"] {
            return Err(VersionError::Malformed);
        }
        if is_describe_form(&v.pre) {
            return Err(VersionError::Malformed);
        }
        Ok(Candidate::Exact(v))
    }

    fn same_identity(&self, a: &str, b: &str) -> Option<bool> {
        let (a, b) = (self.parse(a).ok()?, self.parse(b).ok()?);
        Some(a.identity() == b.identity())
    }

    fn reads_semver_ranges(&self) -> bool {
        true
    }

    fn orders(&self) -> bool {
        true
    }
}

/// Whether a prerelease reads as git-describe output: it ends in `dirty`, or in
/// `<digits>-g<4 to 64 hex digits>` (the prerelease text split on `-`).
fn is_describe_form(pre: &[PreId]) -> bool {
    if pre.is_empty() {
        return false;
    }
    let text = pre
        .iter()
        .map(|id| match id {
            PreId::Numeric(n) => n.to_string(),
            PreId::Text(t) => t.clone(),
        })
        .collect::<Vec<_>>()
        .join(".");
    let parts: Vec<&str> = text.split('-').collect();
    let Some(last) = parts.last() else {
        return false;
    };
    if last.eq_ignore_ascii_case("dirty") {
        return true;
    }
    let hash_like = last
        .strip_prefix('g')
        .is_some_and(|h| (4..=64).contains(&h.len()) && h.bytes().all(|b| b.is_ascii_hexdigit()));
    let count_like = parts
        .len()
        .checked_sub(2)
        .and_then(|i| parts.get(i))
        .is_some_and(|c| !c.is_empty() && c.bytes().all(|b| b.is_ascii_digit()));
    parts.len() >= 2 && count_like && hash_like
}
