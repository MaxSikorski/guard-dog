//! Core Lightning's `calver` scheme (design 2.1, section 2, "CLN (M6)").
//!
//! One scheme reads three kinds of text: legacy releases `0.x.y[rcN]`, calendar
//! releases `YY.MM[.N][rcN]`, and a build described by git (`v24.11-12-gabc1234`,
//! with CLN's `-modded` dirty marker). Only the first two are versions with an
//! order. A described build is an interval above its tag ([`Calver::candidate`]),
//! never a version, so it can never be a range boundary.

use std::cmp::Ordering;
use std::fmt;

use super::describe::{Described, split_describe};
use super::num::Num;
use super::semver::check_length;
use super::{Candidate, VersionError, VersionScheme};

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
    a: Num,
    /// Legacy: `y`. Calendar: the month, 1 to 12.
    b: Num,
    /// Calendar: the patch number (0 when not written). Legacy: 0.
    c: Num,
    /// The release candidate number, if any.
    rc: Option<Num>,
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
    check_length(raw)?;
    let s = raw.strip_prefix('v').unwrap_or(raw);
    let (core, rc) = match s.split_once("rc") {
        Some((core, rc)) => (core, Some(Num::strict(rc).ok_or(VersionError::Malformed)?)),
        None => (s, None),
    };
    let parts: Vec<&str> = core.split('.').collect();
    let plain = |t: &str| Num::strict(t).ok_or(VersionError::Malformed);
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
                a: Num::trimmed(yy).ok_or(VersionError::Malformed)?,
                b: Num::trimmed(mm).ok_or(VersionError::Malformed)?,
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

    /// A release tag is exact. (Why a bare CLN tag is exact while strfry's bare
    /// tag is an interval: the release tarball and `getinfo` report the release
    /// itself, whereas strfry's version comes from `git describe`, which says
    /// only that the build is at or after its tag.) A clean describe string descends from its tag
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

    /// Identity is the canonical text of a release tag (`v24.11` is `24.11.0`).
    /// A describe string is not a release: if either side is one (or anything
    /// else `parse` refuses) the answer is `None`, never "different".
    fn same_identity(&self, a: &str, b: &str) -> Option<bool> {
        let a = parse_tag(a).ok()?;
        let b = parse_tag(b).ok()?;
        Some(a.to_string() == b.to_string())
    }

    fn reads_semver_ranges(&self) -> bool {
        false
    }

    fn orders(&self) -> bool {
        true
    }
}
