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

use super::{VersionError, VersionScheme};
use crate::MAX_VERSION_BYTES;

/// Most dot-separated identifiers accepted in a prerelease or in metadata.
pub(crate) const MAX_COMPONENTS: usize = 64;

/// A non-negative decimal number with no leading zeros (`0` is `"0"`).
/// Compared by length, then bytes.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(crate) struct Num(String);

impl Num {
    pub(crate) fn zero() -> Self {
        Self("0".to_string())
    }

    /// This number plus one.
    pub(crate) fn plus_one(&self) -> Self {
        let mut digits: Vec<u8> = self.0.bytes().collect();
        let mut i = digits.len();
        loop {
            match i.checked_sub(1) {
                Some(j) => {
                    if let Some(d) = digits.get_mut(j) {
                        if *d == b'9' {
                            *d = b'0';
                        } else {
                            *d += 1;
                            break;
                        }
                    }
                    i = j;
                }
                None => {
                    digits.insert(0, b'1');
                    break;
                }
            }
        }
        Self(String::from_utf8_lossy(&digits).into_owned())
    }
}

impl Ord for Num {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0
            .len()
            .cmp(&other.0.len())
            .then_with(|| self.0.as_bytes().cmp(other.0.as_bytes()))
    }
}
impl PartialOrd for Num {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl fmt::Display for Num {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Reads ASCII digits only, nonempty, with no leading zero.
pub(crate) fn parse_num(s: &str) -> Result<Num, VersionError> {
    let bytes = s.as_bytes();
    if bytes.is_empty() || !bytes.iter().all(u8::is_ascii_digit) {
        return Err(VersionError::Malformed);
    }
    if bytes.len() > 1 && bytes.first() == Some(&b'0') {
        return Err(VersionError::Malformed);
    }
    Ok(Num(s.to_string()))
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
