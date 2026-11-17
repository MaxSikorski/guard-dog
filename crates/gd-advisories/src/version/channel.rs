//! The `semver-beta` channel scheme (design 2.1, section 2, "Channel releases").
//!
//! LND ships `X.Y.Z-beta` and `X.Y.Z-beta.rcN`; Lightning Terminal ships
//! `X.Y.Z-alpha` and `X.Y.Z-alpha.rcN`. Strict SemVer puts `0.20.0-beta.rc1`
//! above `0.20.0-beta`; the products order the other way. This scheme keeps the
//! products' order: `rcN` (numeric) < channel release. A bare `X.Y.Z` is
//! refused by the channel parser. The channel is never erased: it is part of
//! the identity.
//!
//! One scheme object has one order. A channel product's SEMVER and Go ranges are
//! checked in both orders by [`evaluate_channel_entry`].

use std::cmp::Ordering;
use std::fmt;

use crate::MAX_VERSION_BYTES;

use super::num::Num;
use super::semver::{check_length, parse_num};
use super::{GoTag, SemVer, SemVerVersion, VersionError, VersionScheme};
use crate::osv::{Advisory, RangeKind};
use crate::range::{
    Place, UnknownReason, VersionEvidence, evaluate_entry, evaluate_entry_with, unknown,
};

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
/// order: release candidates, then the channel release.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
enum StageKind {
    Rc,
    Release,
}

/// A channel version. Order: numeric triple, then release candidate (by
/// number) < channel release.
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

    fn key(&self) -> (&Num, &Num, &Num, StageKind, &Channel, Option<&Num>) {
        let rc = (self.kind == StageKind::Rc).then_some(&self.rc);
        (
            &self.major,
            &self.minor,
            &self.patch,
            self.kind,
            &self.channel,
            rc,
        )
    }
}

impl fmt::Display for ChannelVersion {
    /// The canonical text; the `-rcN` alias is written `-<channel>.rcN`.
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}.{}.{}", self.major, self.minor, self.patch)?;
        match self.kind {
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
        check_length(raw)?;
        let s = raw.strip_prefix('v').unwrap_or(raw);
        // A bare `X.Y.Z` is refused: the channel is part of the version.
        let (core, rest) = s.split_once('-').ok_or(VersionError::Malformed)?;
        let mut parts = core.split('.');
        let (Some(a), Some(b), Some(c), None) =
            (parts.next(), parts.next(), parts.next(), parts.next())
        else {
            return Err(VersionError::Malformed);
        };
        let (major, minor, patch) = (parse_num(a)?, parse_num(b)?, parse_num(c)?);
        let name = self.channel.name();
        let (kind, rc) = match rest {
            r if r == name => (StageKind::Release, Num::zero()),
            r => {
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
        let version = ChannelVersion {
            major,
            minor,
            patch,
            kind,
            channel: self.channel,
            rc,
        };
        // The canonical text can be longer than the input (the `-rcN` alias
        // gains the channel name); it must still fit the limit.
        if version.to_string().len() > MAX_VERSION_BYTES {
            return Err(VersionError::TooLong);
        }
        Ok(version)
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

    /// Channel ranges are SemVer-shaped, but only [`evaluate_channel_entry`] may
    /// answer them, through its own crate-private wrapper: the bare scheme
    /// answers no entry at all (`answers_alone`).
    fn reads_semver_ranges(&self) -> bool {
        false
    }

    /// The same for Go `ECOSYSTEM` ranges: the bare scheme answers no entry at
    /// all (`answers_alone`).
    fn reads_ecosystem_ranges(&self) -> bool {
        false
    }

    fn orders(&self) -> bool {
        true
    }

    fn answers_alone(&self) -> bool {
        false
    }
}

/// The channel scheme as the dual check uses it: the same parser and order, with
/// the SemVer-range declaration switched on. Crate-private, so no caller can
/// answer a `SEMVER` range with one order alone.
struct DualChannel<'a>(&'a ChannelScheme);

impl VersionScheme for DualChannel<'_> {
    type Version = ChannelVersion;

    fn parse(&self, raw: &str) -> Result<ChannelVersion, VersionError> {
        self.0.parse(raw)
    }

    fn same_identity(&self, a: &str, b: &str) -> Option<bool> {
        self.0.same_identity(a, b)
    }

    fn reads_semver_ranges(&self) -> bool {
        true
    }

    fn reads_ecosystem_ranges(&self) -> bool {
        true
    }

    fn orders(&self) -> bool {
        self.0.orders()
    }

    fn answers_alone(&self) -> bool {
        true
    }
}

/// The one public way to check LND (beta) or Lightning Terminal (alpha) against
/// an advisory entry. It always runs the dual-order check ([`dual_check`]).
/// The channel scheme alone never answers an entry.
#[must_use]
pub fn evaluate_channel_entry(
    channel_scheme: &ChannelScheme,
    advisory: &Advisory,
    entry_index: usize,
    installed: Option<&str>,
) -> VersionEvidence {
    dual_check(channel_scheme, advisory, entry_index, installed)
}

/// The dual-order check for a channel product on `SEMVER` and Go ranges.
///
/// The channel side runs the evaluator with the channel scheme (its own order,
/// `SEMVER` ranges enabled). The literal side runs it in SemVer order, reading:
/// - the installed value and the listed versions with [`GoTag`], the declared
///   `v` adapter for catalog values and Go module versions;
/// - each `SEMVER` range's boundaries with strict [`SemVer`], because OSV
///   `SEMVER` boundaries carry no `v`;
/// - each `ECOSYSTEM` (Go) range's boundaries with [`GoTag`].
///
/// The answers combine as follows:
/// - in range only if both say in range;
/// - out of range only if both say out of range;
/// - both unknown: the more fundamental reason (the evaluator's own order), the
///   channel scheme's on a tie;
/// - exactly one unknown (one parser could not read something): that side's own
///   reason and place. The other side's answer is never used alone;
/// - in range against out of range: `Unknown(SchemeConflict)`, the real
///   disagreement between the two orders.
fn dual_check(
    channel_scheme: &ChannelScheme,
    advisory: &Advisory,
    entry_index: usize,
    installed: Option<&str>,
) -> VersionEvidence {
    let a = evaluate_entry(
        &DualChannel(channel_scheme),
        advisory,
        entry_index,
        installed,
    );
    let b = evaluate_entry_with(
        &GoTag,
        &|k: &RangeKind| -> &dyn VersionScheme<Version = SemVerVersion> {
            if matches!(k, RangeKind::Semver) {
                &SemVer
            } else {
                &GoTag
            }
        },
        advisory,
        entry_index,
        installed,
    );
    combine(entry_index, a, b)
}

/// Combines the channel scheme's answer `a` with the SemVer answer `b`.
fn combine(entry_index: usize, a: VersionEvidence, b: VersionEvidence) -> VersionEvidence {
    match (a, b) {
        (VersionEvidence::InRange(at), VersionEvidence::InRange(_)) => VersionEvidence::InRange(at),
        (VersionEvidence::OutOfRange, VersionEvidence::OutOfRange) => VersionEvidence::OutOfRange,
        (VersionEvidence::NotApplicable, VersionEvidence::NotApplicable) => {
            VersionEvidence::NotApplicable
        }
        (u @ VersionEvidence::Unknown { .. }, v @ VersionEvidence::Unknown { .. }) => {
            let smaller_b = matches!(
                (&u, &v),
                (
                    VersionEvidence::Unknown { reason: ra, .. },
                    VersionEvidence::Unknown { reason: rb, .. },
                ) if rb < ra
            );
            if smaller_b { v } else { u }
        }
        (u @ VersionEvidence::Unknown { .. }, _) | (_, u @ VersionEvidence::Unknown { .. }) => u,
        _ => unknown(entry_index, Place::Entry, UnknownReason::SchemeConflict),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::range::Location;

    fn at(index: usize) -> Place {
        Place::Listed { index }
    }

    fn reason_and_place(e: &VersionEvidence) -> Option<(UnknownReason, Place)> {
        match e {
            VersionEvidence::Unknown { reason, at, .. } => Some((*reason, at.place)),
            _ => None,
        }
    }

    #[test]
    fn both_unknown_keeps_the_smaller_reason_whichever_side_has_it() {
        let early = || unknown(0, at(1), UnknownReason::UnreadableListedVersion);
        let late = || unknown(0, at(2), UnknownReason::SameVersionDifferentSpelling);
        let want = Some((UnknownReason::UnreadableListedVersion, at(1)));
        // The channel side has the smaller reason, then the SemVer side does.
        assert_eq!(reason_and_place(&combine(0, early(), late())), want);
        assert_eq!(reason_and_place(&combine(0, late(), early())), want);
    }

    #[test]
    fn both_unknown_with_one_reason_keeps_the_channel_sides_place() {
        let a = unknown(0, at(1), UnknownReason::UnparseableBoundary);
        let b = unknown(0, at(2), UnknownReason::UnparseableBoundary);
        assert_eq!(
            reason_and_place(&combine(0, a, b)),
            Some((UnknownReason::UnparseableBoundary, at(1)))
        );
    }

    #[test]
    fn one_unknown_side_speaks_for_itself_in_either_position() {
        let u = || unknown(0, at(3), UnknownReason::UnparseableLimit);
        let in_range = || {
            VersionEvidence::InRange(Location {
                entry: 0,
                place: Place::Entry,
            })
        };
        let want = Some((UnknownReason::UnparseableLimit, at(3)));
        for (a, b) in [
            (u(), in_range()),
            (in_range(), u()),
            (u(), VersionEvidence::OutOfRange),
            (VersionEvidence::OutOfRange, u()),
        ] {
            assert_eq!(reason_and_place(&combine(0, a, b)), want);
        }
    }

    #[test]
    fn only_a_real_order_disagreement_is_a_scheme_conflict() {
        let in_range = || {
            VersionEvidence::InRange(Location {
                entry: 0,
                place: Place::Entry,
            })
        };
        for (a, b) in [
            (in_range(), VersionEvidence::OutOfRange),
            (VersionEvidence::OutOfRange, in_range()),
        ] {
            assert_eq!(
                reason_and_place(&combine(0, a, b)),
                Some((UnknownReason::SchemeConflict, Place::Entry))
            );
        }
    }
}
