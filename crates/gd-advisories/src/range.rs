//! Evaluates one affected entry's ranges and listed versions for one installed
//! version (design 2.1, section 3).

use crate::VersionScheme;
use crate::osv::AffectedEntry;

/// Where a piece of evidence comes from.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum Place {
    /// The entry as a whole.
    Entry,
    /// A range, and the event inside it that decided the result, if one did.
    Range {
        /// Index in `AffectedEntry::ranges`.
        range: usize,
        /// Index in `Range::events`.
        event: Option<usize>,
    },
    /// An item of `AffectedEntry::versions`.
    Listed {
        /// Index in `AffectedEntry::versions`.
        index: usize,
    },
}

/// An entry index and a place in it.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Location {
    /// Index in `Advisory::affected`.
    pub entry: usize,
    /// Where inside the entry.
    pub place: Place,
}

/// Why a result is unknown.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum UnknownReason {
    /// The installed version is not known.
    InstalledVersionUnknown,
    /// The scheme cannot read the installed version.
    InstalledVersionUnparseable,
    /// A `SEMVER` range met a scheme that has not declared SemVer compatibility.
    SchemeMismatch,
    /// A `GIT` range needs a commit graph this library does not have.
    NoCommitGraph,
    /// A range type this version does not know.
    UnsupportedRangeType,
    /// An event kind this version does not know.
    UnknownEventKind,
    /// A boundary the scheme cannot read.
    UnparseableBoundary,
    /// A limit the scheme cannot read.
    UnparseableLimit,
    /// A range with a malformed shape (no events, no `introduced`, both `fixed`
    /// and `last_affected`, or `"0"` on a non-`introduced` event).
    MalformedRange,
    /// Two different event kinds at the same coordinate.
    ConflictingEvents,
    /// A listed version the scheme cannot compare with the installed one.
    UnreadableListedVersion,
    /// The entry has no usable range and no listed version.
    NoUsableRangeOrVersions,
}

/// What the advisory says about one installed version.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum VersionEvidence {
    /// Affected, and where that was decided.
    InRange(Location),
    /// Not affected: every range and list excluded it, completely.
    OutOfRange,
    /// Cannot say. The question is plain text for the user and never contains
    /// text from the advisory.
    Unknown {
        /// Why.
        reason: UnknownReason,
        /// What to ask.
        question: String,
        /// The most relevant place.
        at: Location,
    },
    /// The advisory does not concern this installation. A later scope step
    /// produces it; this module never does.
    NotApplicable,
}

/// Evaluates one entry (at `entry_index`) for `installed` with the caller's
/// `scheme`.
pub fn evaluate_entry<S: VersionScheme + ?Sized>(
    scheme: &S,
    entry_index: usize,
    entry: &AffectedEntry,
    installed: Option<&str>,
) -> VersionEvidence {
    let _ = (scheme, entry, installed);
    VersionEvidence::Unknown {
        reason: UnknownReason::NoUsableRangeOrVersions,
        question: String::new(),
        at: Location {
            entry: entry_index,
            place: Place::Entry,
        },
    }
}
