//! The `semver-beta` channel scheme (design 2.1, section 2, "Channel releases").
//!
//! LND ships `X.Y.Z-beta` and `X.Y.Z-beta.rcN`; Lightning Terminal ships
//! `X.Y.Z-alpha` and `X.Y.Z-alpha.rcN`. Strict SemVer puts `0.20.0-beta.rc1`
//! above `0.20.0-beta`; the products order the other way. This scheme keeps the
//! products' order: `rcN` (numeric) < channel release < bare final. The channel
//! is never erased: it is part of the identity.
//!
//! One scheme object has one order. A channel product's SEMVER and Go ranges are
//! checked in both orders by [`dual_check`].

use std::cmp::Ordering;
use std::fmt;

use super::semver::{Num, check_length, parse_num};
use super::{VersionError, VersionScheme};
use crate::osv::Advisory;
use crate::range::{Place, UnknownReason, VersionEvidence, evaluate_entry, unknown};

/// A release channel, as the catalog's `channel` names it.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
pub enum Channel {
    /// Lightning Terminal.
    Alpha,
    /// LND.
    Beta,
}

impl Channel {
    /// Reads the catalog's `channel` value.
    #[must_use]
    pub fn from_name(name: &str) -> Option<Self> {
        match name {
            "alpha" => Some(Self::Alpha),
            "beta" => Some(Self::Beta),
            _ => None,
        }
    }

    /// The catalog name and the version suffix.
    #[must_use]
    pub fn name(self) -> &'static str {
        match self {
            Self::Alpha => "alpha",
            Self::Beta => "beta",
        }
    }
}

/// Where a version sits after its numbers. The derived order is the products'
/// order: release candidates, then the channel release, then the final.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum StageKind {
    Rc,
    Release,
    Final,
}

/// A channel version. Order: numeric triple, then release candidate (by
/// number) < channel release < bare final.
#[derive(Clone, Debug)]
pub struct ChannelVersion {
    major: Num,
    minor: Num,
    patch: Num,
    kind: StageKind,
    channel: Channel,
    rc: Num,
}

impl ChannelVersion {
    /// The channel this version carries.
    #[must_use]
    pub fn channel(&self) -> Channel {
        self.channel
    }

    fn key(&self) -> (&Num, &Num, &Num, StageKind, Option<&Channel>, Option<&Num>) {
        let channel = (self.kind != StageKind::Final).then_some(&self.channel);
        let rc = (self.kind == StageKind::Rc).then_some(&self.rc);
        (
            &self.major,
            &self.minor,
            &self.patch,
            self.kind,
            channel,
            rc,
        )
    }
}

impl fmt::Display for ChannelVersion {
    /// The canonical text; the `-rcN` alias is written `-<channel>.rcN`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)?;
        match self.kind {
            StageKind::Final => Ok(()),
            StageKind::Release => write!(f, "-{}", self.channel.name()),
            StageKind::Rc => write!(f, "-{}.rc{}", self.channel.name(), self.rc),
        }
    }
}

impl Ord for ChannelVersion {
    fn cmp(&self, other: &Self) -> Ordering {
        self.key().cmp(&other.key())
    }
}
impl PartialOrd for ChannelVersion {
    fn partial_cmp(&self, other: &Self) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}
impl PartialEq for ChannelVersion {
    fn eq(&self, other: &Self) -> bool {
        self.cmp(other) == Ordering::Equal
    }
}
impl Eq for ChannelVersion {}

/// The channel scheme for one channel.
#[derive(Clone, Copy, Debug)]
pub struct ChannelScheme {
    channel: Channel,
}

impl ChannelScheme {
    /// The scheme for `channel`.
    #[must_use]
    pub fn new(channel: Channel) -> Self {
        Self { channel }
    }

    /// LND.
    #[must_use]
    pub fn beta() -> Self {
        Self::new(Channel::Beta)
    }

    /// Lightning Terminal.
    #[must_use]
    pub fn alpha() -> Self {
        Self::new(Channel::Alpha)
    }

    /// The channel.
    #[must_use]
    pub fn channel(&self) -> Channel {
        self.channel
    }

    fn read(&self, raw: &str) -> Result<ChannelVersion, VersionError> {
        if !raw.is_empty() || raw.is_empty() {
            return Err(VersionError::Malformed); // stub: tests first
        }
        check_length(raw)?;
        let s = raw.strip_prefix('v').unwrap_or(raw);
        let (core, rest) = match s.split_once('-') {
            Some((c, r)) => (c, Some(r)),
            None => (s, None),
        };
        let mut parts = core.split('.');
        let (Some(a), Some(b), Some(c), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(VersionError::Malformed);
        };
        let (major, minor, patch) = (parse_num(a)?, parse_num(b)?, parse_num(c)?);
        let name = self.channel.name();
        let (kind, rc) = match rest {
            None => (StageKind::Final, Num::zero()),
            Some(r) if r == name => (StageKind::Release, Num::zero()),
            Some(r) => {
                // `-rcN` is an alias of `-<channel>.rcN`.
                let n = r
                    .strip_prefix("rc")
                    .or_else(|| r.strip_prefix(name).and_then(|t| t.strip_prefix(".rc")))
                    .ok_or(VersionError::Malformed)?;
                let n = parse_num(n)?;
                if n == Num::zero() {
                    return Err(VersionError::Malformed);
                }
                (StageKind::Rc, n)
            }
        };
        Ok(ChannelVersion {
            major,
            minor,
            patch,
            kind,
            channel: self.channel,
            rc,
        })
    }
}

impl VersionScheme for ChannelScheme {
    type Version = ChannelVersion;

    fn parse(&self, raw: &str) -> Result<ChannelVersion, VersionError> {
        self.read(raw)
    }

    /// Identity is the canonical text: the `v` and the `-rcN` alias are the only
    /// normalizations, and the channel is kept.
    fn same_identity(&self, a: &str, b: &str) -> Option<bool> {
        let (a, b) = (self.read(a).ok()?, self.read(b).ok()?);
        Some(a.to_string() == b.to_string())
    }

    /// Channel ranges are SemVer-shaped, but only the dual check
    /// ([`dual_check`]) may answer them.
    fn reads_semver_ranges(&self) -> bool {
        true
    }

    fn orders(&self) -> bool {
        true
    }
}

/// The dual-order check for a channel product on `SEMVER` and Go ranges.
///
/// The caller passes the channel scheme and the literal SemVer scheme (with the
/// declared `v` adapter, [`GoTag`](super::GoTag)); each runs the evaluator on the
/// same entry and installed value. The answers combine as follows:
/// - in range only if both say in range;
/// - out of range only if both say out of range;
/// - both unknown: the more fundamental reason (the evaluator's own order);
/// - anything else, including one parser failing while the other answers, is
///   `Unknown(SchemeConflict)`. Neither parser's answer is used alone.
pub fn dual_check<A, B>(
    channel_scheme: &A,
    semver_scheme: &B,
    advisory: &Advisory,
    entry_index: usize,
    installed: Option<&str>,
) -> VersionEvidence
where
    A: VersionScheme + ?Sized,
    B: VersionScheme + ?Sized,
{
    let a = evaluate_entry(channel_scheme, advisory, entry_index, installed);
    let b = evaluate_entry(semver_scheme, advisory, entry_index, installed);
    match (a, b) {
        (VersionEvidence::InRange(at), VersionEvidence::InRange(_)) => VersionEvidence::InRange(at),
        (VersionEvidence::OutOfRange, VersionEvidence::OutOfRange) => VersionEvidence::OutOfRange,
        (VersionEvidence::NotApplicable, VersionEvidence::NotApplicable) => {
            VersionEvidence::NotApplicable
        }
        (u @ VersionEvidence::Unknown { .. }, v @ VersionEvidence::Unknown { .. }) => {
            // Both orders are unknown: report the earlier reason, from the
            // channel scheme on a tie.
            match (&u, &v) {
                (
                    VersionEvidence::Unknown { reason: ra, .. },
                    VersionEvidence::Unknown { reason: rb, .. },
                ) if rb < ra => v,
                _ => u,
            }
        }
        _ => unknown(entry_index, Place::Entry, UnknownReason::SchemeConflict),
    }
}
