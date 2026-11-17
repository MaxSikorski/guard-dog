//! Bitcoin Core's `bitcoin-core` scheme (design 2.1, section 2, "Bitcoin Core").
//!
//! Optional `v`, then `major.minor[.patch][rcN]`. An absent patch is 0, a release
//! candidate sorts below its final release, and numbers have no leading zeros.
//! Historical numbering is not rewritten: `0.21.1 < 22.0`. Release candidates
//! are numbered from 1 here, so `rc0` is refused. The old four-part
//! numbers of the 0.x.y.z releases (`0.9.2.1`) are refused too.
//!
//! The catalog extracts `32.1` from `/Satoshi:32.1.0/`; this parser never
//! searches banners.

use std::cmp::Ordering;
use std::fmt;

use super::semver::{Num, check_length, parse_num};
use super::{Candidate, VersionError, VersionScheme};

/// Whether the installed value's source would have shown a release candidate.
///
/// `getnetworkinfo.subversion` is built from the numeric client version and
/// omits `rcN`, so a `28.3rc1` node reads as `28.3`. The caller says which kind
/// of source it has; there is deliberately no default.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum RcEvidence {
    /// The source carries the full version, including any `rcN` (for example
    /// `bitcoind -version`). A value without `rcN` is a final release.
    Reported,
    /// The source drops `rcN` (the `subversion` field). A value without `rcN`
    /// may be the final release or any release candidate of it.
    Unknown,
}

/// A Bitcoin Core release. Order is the numeric tuple, then release candidates
/// below the final release.
#[derive(Clone, Debug)]
pub struct CoreVersion {
    major: Num,
    minor: Num,
    patch: Num,
    rc: Option<Num>,
}

impl fmt::Display for CoreVersion {
    /// The canonical text: always three numbers, then `rcN` if any.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)?;
        if let Some(rc) = &self.rc {
            write!(f, "rc{rc}")?;
        }
        Ok(())
    }
}

impl Ord for CoreVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        self.major
            .cmp(&other.major)
            .then_with(|| self.minor.cmp(&other.minor))
            .then_with(|| self.patch.cmp(&other.patch))
            .then_with(|| match (&self.rc, &other.rc) {
                (None, None) => Ordering::Equal,
                (None, Some(_)) => Ordering::Greater,
                (Some(_), None) => Ordering::Less,
                (Some(a), Some(b)) => a.cmp(b),
            })
    }
}
impl PartialOrd for CoreVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl PartialEq for CoreVersion {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}
impl Eq for CoreVersion {}

fn read(raw: &str) -> Result<CoreVersion, VersionError> {
    check_length(raw)?;
    let s = raw.strip_prefix('v').unwrap_or(raw);
    let (base, rc) = match s.split_once("rc") {
        Some((b, n)) => {
            let n = parse_num(n)?;
            if n == Num::zero() {
                return Err(VersionError::Malformed);
            }
            (b, Some(n))
        }
        None => (s, None),
    };
    let mut parts = base.split('.');
    let (Some(a), Some(b), c, None) = (parts.next(), parts.next(), parts.next(), parts.next())
    else {
        return Err(VersionError::Malformed);
    };
    Ok(CoreVersion {
        major: parse_num(a)?,
        minor: parse_num(b)?,
        patch: match c {
            Some(c) => parse_num(c)?,
            None => Num::zero(),
        },
        rc,
    })
}

/// The Bitcoin Core scheme. Advisory boundaries always go through [`parse`];
/// only the installed value is affected by [`RcEvidence`].
///
/// [`parse`]: VersionScheme::parse
#[derive(Clone, Copy, Debug)]
pub struct BitcoinCore {
    installed_rc: RcEvidence,
}

impl BitcoinCore {
    /// A scheme whose installed values come from a source with the given
    /// release-candidate evidence.
    #[must_use]
    pub fn new(installed_rc: RcEvidence) -> Self {
        Self { installed_rc }
    }
}

impl VersionScheme for BitcoinCore {
    type Version = CoreVersion;

    fn parse(&self, raw: &str) -> Result<CoreVersion, VersionError> {
        read(raw)
    }

    /// With [`RcEvidence::Unknown`], a value without `rcN` is the interval from
    /// the lowest release candidate of that release up to, and including, the
    /// final release (the end, exclusive, is just below the first release
    /// candidate of the next patch). A range that treats the two differently
    /// therefore ends unknown.
    ///
    /// Four-part numbers from the 0.x.y.z releases (`0.9.2.1`) are refused, like
    /// every other form this scheme does not read.
    fn candidate(&self, raw: &str) -> Result<Candidate<CoreVersion>, VersionError> {
        let v = read(raw)?;
        if self.installed_rc == RcEvidence::Unknown && v.rc.is_none() {
            let low = CoreVersion {
                rc: Some(Num::zero()),
                ..v.clone()
            };
            // Just below the first release candidate of the next patch: a value
            // that may be any rc of the next release is not inside the interval.
            let high = CoreVersion {
                patch: v.patch.plus_one(),
                rc: Some(Num::zero()),
                ..v
            };
            return Ok(Candidate::Between {
                low,
                high: Some(high),
            });
        }
        Ok(Candidate::Exact(v))
    }

    /// The release-candidate question of design 2.1 section 2.
    fn interval_question(&self) -> &'static str {
        "What full version does bitcoind report, including any rcN?"
    }

    /// Identity is the canonical text: an absent patch is 0, so `28.1` and
    /// `v28.1.0` are the same release.
    fn same_identity(&self, a: &str, b: &str) -> Option<bool> {
        let (a, b) = (read(a).ok()?, read(b).ok()?);
        Some(a.to_string() == b.to_string())
    }

    /// Core's ranges are `ECOSYSTEM`; a `SEMVER` range needs a reviewed
    /// interpretation first, so it stays unknown.
    fn reads_semver_ranges(&self) -> bool {
        false
    }

    fn orders(&self) -> bool {
        true
    }
}
