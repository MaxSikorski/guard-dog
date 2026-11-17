//! Core Lightning's `calver` scheme (design 2.1, section 2, "CLN (M6)").
//!
//! One scheme reads three kinds of text: legacy releases `0.x.y[rcN]`, calendar
//! releases `YY.MM[.N][rcN]`, and a build described by git (`v24.11-12-gabc1234`,
//! with CLN's `-modded` dirty marker). Only the first two are versions with an
//! order. A described build is an interval above its tag ([`Calver::candidate`]),
//! never a version, so it can never be a range boundary.

use std::cmp::Ordering;
use std::fmt;

use super::describe::{Described, identity_text, split_describe};
use super::{Candidate, VersionError, VersionScheme};

/// The longest version string any scheme reads, in bytes (design 2.1, section 1).
pub(super) const MAX_LEN: usize = 256;
/// The most dot-separated components any scheme reads (design 2.1, section 1).
pub(super) const MAX_COMPONENTS: usize = 64;

/// A non-negative decimal number of any size, kept as normalized digits (no
/// leading zeros) and compared by length, then bytes. No overflow, no bigint
/// dependency.
///
/// Shared by the schemes in this directory; it is to be unified with the
/// SemVer and Bitcoin Core parsers' own copy once those land.
#[derive(Clone, Debug, PartialEq, Eq)]
pub(super) struct Dec(String);

impl Dec {
    /// ASCII digits only, any leading zeros; the stored form has none.
    pub(super) fn parse(s: &str) -> Option<Self> {
        if s.is_empty() || !s.bytes().all(|b| b.is_ascii_digit()) {
            return None;
        }
        let t = s.trim_start_matches('0');
        Some(Self(if t.is_empty() {
            "0".to_string()
        } else {
            t.to_string()
        }))
    }

    /// Like [`Dec::parse`], but a leading zero (other than `0` alone) is refused.
    pub(super) fn parse_plain(s: &str) -> Option<Self> {
        if s.len() > 1 && s.starts_with('0') {
            None
        } else {
            Self::parse(s)
        }
    }

    pub(super) fn is_zero(&self) -> bool {
        self.0 == "0"
    }

    pub(super) fn as_str(&self) -> &str {
        &self.0
    }
}

impl Ord for Dec {
    fn cmp(&self, other: &Self) -> Ordering {
        self.0
            .len()
            .cmp(&other.0.len())
            .then_with(|| self.0.cmp(&other.0))
    }
}

impl PartialOrd for Dec {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl fmt::Display for Dec {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(&self.0)
    }
}

/// Core Lightning's version scheme.
///
/// Orders legacy `0.x.y[rcN]` below calendar `YY.MM[.N][rcN]`; within each, by
/// numbers (never text) with a release candidate below its final release.
#[derive(Clone, Copy, Debug, Default)]
pub struct Calver;

/// One Core Lightning release: a legacy `0.x.y` or a calendar `YY.MM.N`, with an
/// optional release candidate number.
///
/// `Ord` is the release order and `Eq` agrees with it, so `24.11` and `24.11.0`
/// are equal here; they are the same release, spelled two ways.
#[derive(Clone, Debug)]
pub struct ClnVersion {
    /// Legacy `0.x.y` releases sit below every calendar release.
    legacy: bool,
    /// Legacy: `x`. Calendar: the two-digit year.
    a: Dec,
    /// Legacy: `y`. Calendar: the month, 1 to 12.
    b: Dec,
    /// Calendar: the patch number (0 when not written). Legacy: 0.
    c: Dec,
    /// The release candidate number, if any.
    rc: Option<Dec>,
}

impl ClnVersion {
    /// Whether this is a legacy `0.x.y` release (below every calendar release).
    #[must_use]
    pub fn is_legacy(&self) -> bool {
        self.legacy
    }
}

impl Ord for ClnVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        // Legacy (true) sorts below calendar (false), hence the reversal.
        other
            .legacy
            .cmp(&self.legacy)
            .then_with(|| self.a.cmp(&other.a))
            .then_with(|| self.b.cmp(&other.b))
            .then_with(|| self.c.cmp(&other.c))
            .then_with(|| match (&self.rc, &other.rc) {
                (None, None) => Ordering::Equal,
                (Some(_), None) => Ordering::Less,
                (None, Some(_)) => Ordering::Greater,
                (Some(x), Some(y)) => x.cmp(y),
            })
    }
}

impl PartialOrd for ClnVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

impl PartialEq for ClnVersion {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}

impl Eq for ClnVersion {}

/// The canonical text: no `v`, the patch always written, `YY` and `MM` with two
/// digits. Reading it back gives an equal version.
impl fmt::Display for ClnVersion {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        if self.legacy {
            write!(f, "0.{}.{}", self.a, self.b)?;
        } else {
            write!(
                f,
                "{:0>2}.{:0>2}.{}",
                self.a.as_str(),
                self.b.as_str(),
                self.c
            )?;
        }
        if let Some(rc) = &self.rc {
            write!(f, "rc{rc}")?;
        }
        Ok(())
    }
}

/// Reads one release tag: optional `v`, then legacy or calendar, then an
/// optional `rcN`. The whole string, or nothing.
fn parse_tag(raw: &str) -> Result<ClnVersion, VersionError> {
    if raw.len() > MAX_LEN {
        return Err(VersionError::TooLong);
    }
    let s = raw.strip_prefix('v').unwrap_or(raw);
    let (core, rc) = match s.split_once("rc") {
        Some((core, rc)) => (
            core,
            Some(Dec::parse_plain(rc).ok_or(VersionError::Malformed)?),
        ),
        None => (s, None),
    };
    let parts: Vec<&str> = core.split('.').collect();
    let plain = |t: &str| Dec::parse_plain(t).ok_or(VersionError::Malformed);
    match parts.as_slice() {
        ["0", x, y] => Ok(ClnVersion {
            legacy: true,
            a: plain(x)?,
            b: plain(y)?,
            c: plain("0")?,
            rc,
        }),
        [yy, mm] | [yy, mm, _] => {
            let patch = match parts.get(2) {
                Some(n) => plain(n)?,
                None => plain("0")?,
            };
            if yy.len() != 2 || !is_month(mm) {
                return Err(VersionError::Malformed);
            }
            Ok(ClnVersion {
                legacy: false,
                a: Dec::parse(yy).ok_or(VersionError::Malformed)?,
                b: Dec::parse(mm).ok_or(VersionError::Malformed)?,
                c: patch,
                rc,
            })
        }
        _ => Err(VersionError::Malformed),
    }
}

fn is_month(s: &str) -> bool {
    matches!(
        s,
        "01" | "02" | "03" | "04" | "05" | "06" | "07" | "08" | "09" | "10" | "11" | "12"
    )
}

impl Calver {
    /// Reads a release tag or a describe string, keeping every field: the tag,
    /// the commit distance and hash if there is one, and whether the build is
    /// dirty (`-modded`, CLN's marker, or `-dirty`).
    ///
    /// # Errors
    /// [`VersionError::Malformed`] if the string is not one of those forms (a
    /// hash that is not 4 to 64 lowercase hex, a distance that is not plain
    /// decimal, an unreadable tag); [`VersionError::TooLong`] past 256 bytes.
    pub fn parse_describe(&self, raw: &str) -> Result<Described<ClnVersion>, VersionError> {
        let split = split_describe(raw, &["-modded", "-dirty"])?;
        Ok(Described {
            tag: parse_tag(split.tag)?,
            commit: split.commit,
            dirty: split.dirty,
        })
    }
}

impl VersionScheme for Calver {
    type Version = ClnVersion;

    /// Reads a release tag only. A describe string is not a release, so it is
    /// refused here and can never become a range boundary or a listed version.
    fn parse(&self, raw: &str) -> Result<ClnVersion, VersionError> {
        parse_tag(raw)
    }

    /// A release tag is exact. A clean describe string descends from its tag
    /// (an interval, whatever its distance: distance zero equals the tag only
    /// with a verified tag-to-commit mapping, which does not exist). A modded or
    /// dirty build gives nothing.
    fn candidate(&self, raw: &str) -> Result<Candidate<ClnVersion>, VersionError> {
        let d = self.parse_describe(raw)?;
        if d.dirty {
            return Err(VersionError::Malformed);
        }
        Ok(match d.commit {
            None => Candidate::Exact(d.tag),
            Some(_) => Candidate::Between {
                low: d.tag,
                high: None,
            },
        })
    }

    /// Identity is the canonical text (`v24.11` is `24.11.0`), and for a
    /// described build every field: tag, distance, hash and dirty marker.
    fn same_identity(&self, a: &str, b: &str) -> Option<bool> {
        let a = self.parse_describe(a).ok()?;
        let b = self.parse_describe(b).ok()?;
        Some(identity_text(&a) == identity_text(&b))
    }

    fn reads_semver_ranges(&self) -> bool {
        false
    }

    fn orders(&self) -> bool {
        true
    }
}
