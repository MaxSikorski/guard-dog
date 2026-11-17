//! Evaluates one affected entry's ranges and listed versions for one installed
//! version (design 2.1, section 3).

use crate::VersionScheme;
use crate::osv::{Advisory, AffectedEntry, Event, Range, RangeKind};

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
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
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
    /// The record as a whole is uncertain.
    RecordUncertain,
    /// The scheme has no order, so ranges cannot be evaluated.
    SchemeDoesNotOrder,
    /// A listed version equals the installed one by order but is spelled differently.
    SameVersionDifferentSpelling,
    /// The installed version is only known to lie in an interval.
    CandidateIsAnInterval,
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

fn question(reason: UnknownReason) -> &'static str {
    match reason {
        UnknownReason::InstalledVersionUnknown => {
            "Which version is installed? Guard Dog could not read it from the system."
        }
        UnknownReason::InstalledVersionUnparseable => {
            "The installed version could not be read in this product's version scheme. What is the exact release version?"
        }
        UnknownReason::SchemeMismatch => {
            "This advisory's ranges assume SemVer, but this product uses another version scheme. Which upstream release is installed, and has a reviewed mapping been added for it?"
        }
        UnknownReason::NoCommitGraph => {
            "This advisory names commits, not releases. Which upstream release or tag is this installed version built from?"
        }
        UnknownReason::UnsupportedRangeType => {
            "This advisory uses a range type Guard Dog does not know. Is this version affected according to the advisory's own source?"
        }
        UnknownReason::UnknownEventKind => {
            "This advisory's range has an event Guard Dog does not know. Is this version affected according to the advisory's own source?"
        }
        UnknownReason::UnparseableBoundary => {
            "A boundary in this advisory's range could not be read. Which versions does the advisory's source say are affected?"
        }
        UnknownReason::UnparseableLimit => {
            "A limit in this advisory's range could not be read. Which versions does the advisory's source say are affected?"
        }
        UnknownReason::MalformedRange => {
            "A range in this advisory is incomplete or contradicts itself. Which versions does the advisory's source say are affected?"
        }
        UnknownReason::ConflictingEvents => {
            "This advisory gives two different range events at the same version. Which versions does the advisory's source say are affected?"
        }
        UnknownReason::UnreadableListedVersion => {
            "A version listed in this advisory could not be compared with the installed one. Which versions does the advisory's source say are affected?"
        }
        UnknownReason::RecordUncertain
        | UnknownReason::SchemeDoesNotOrder
        | UnknownReason::SameVersionDifferentSpelling
        | UnknownReason::CandidateIsAnInterval => "stub",
        UnknownReason::NoUsableRangeOrVersions => {
            "This advisory lists no usable range or version for this package. Which versions does the advisory's source say are affected?"
        }
    }
}

fn unknown(entry: usize, place: Place, reason: UnknownReason) -> VersionEvidence {
    VersionEvidence::Unknown {
        reason,
        question: question(reason).to_string(),
        at: Location { entry, place },
    }
}

/// The answer for one range, before the union.
enum Outcome {
    In(Place),
    Out,
    Unknown(UnknownReason, Place),
}

/// Evaluates one entry (at `entry_index`) for `installed` with the caller's
/// `scheme`.
///
/// Ranges and the `versions` list are a union: any positive evidence wins, then
/// any unknown, and only when every range and the whole list exclude the
/// installed version is the answer [`VersionEvidence::OutOfRange`]. The scheme is
/// the caller's choice; the range type never selects a parser.
pub fn evaluate_entry<S: VersionScheme + ?Sized>(
    scheme: &S,
    advisory: &Advisory,
    entry_index: usize,
    installed: Option<&str>,
) -> VersionEvidence {
    match advisory.affected.get(entry_index) {
        Some(entry) => evaluate_inner(scheme, entry_index, entry, installed),
        None => unknown(
            entry_index,
            Place::Entry,
            UnknownReason::NoUsableRangeOrVersions,
        ),
    }
}

fn evaluate_inner<S: VersionScheme + ?Sized>(
    scheme: &S,
    entry_index: usize,
    entry: &AffectedEntry,
    installed: Option<&str>,
) -> VersionEvidence {
    let whole = Place::Entry;
    let Some(raw) = installed else {
        return unknown(entry_index, whole, UnknownReason::InstalledVersionUnknown);
    };
    let candidate = scheme.parse(raw).ok();
    let mut first_unknown: Option<(UnknownReason, Place)> = None;
    let mut note = |reason: UnknownReason, place: Place| {
        if first_unknown.is_none() {
            first_unknown = Some((reason, place));
        }
    };
    if candidate.is_none() {
        note(UnknownReason::InstalledVersionUnparseable, whole);
    }

    let mut positive: Option<Place> = None;
    if let Some(candidate) = &candidate {
        for (index, range) in entry.ranges.iter().enumerate() {
            match eval_range(scheme, index, range, candidate) {
                Outcome::In(place) => {
                    positive.get_or_insert(place);
                }
                Outcome::Out => {}
                Outcome::Unknown(reason, place) => note(reason, place),
            }
        }
    }
    for (index, item) in entry.versions.iter().enumerate() {
        match scheme.same_identity(raw, item.expose_untrusted()) {
            Some(true) => {
                positive.get_or_insert(Place::Listed { index });
            }
            Some(false) => {}
            None => note(
                UnknownReason::UnreadableListedVersion,
                Place::Listed { index },
            ),
        }
    }

    if let Some(place) = positive {
        return VersionEvidence::InRange(Location {
            entry: entry_index,
            place,
        });
    }
    if let Some((reason, place)) = first_unknown {
        return unknown(entry_index, place, reason);
    }
    if entry.ranges.is_empty() && entry.versions.is_empty() {
        return unknown(entry_index, whole, UnknownReason::NoUsableRangeOrVersions);
    }
    VersionEvidence::OutOfRange
}

/// A position on the version line: "0" starts before every version.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Coordinate<V> {
    NegativeInfinity,
    At(V),
}

#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Step {
    Introduced,
    Fixed,
    LastAffected,
}

fn eval_range<S: VersionScheme + ?Sized>(
    scheme: &S,
    range_index: usize,
    range: &Range,
    candidate: &S::Version,
) -> Outcome {
    let shape = Place::Range {
        range: range_index,
        event: None,
    };
    match range.kind {
        RangeKind::Git => return Outcome::Unknown(UnknownReason::NoCommitGraph, shape),
        RangeKind::Semver if !scheme.reads_semver_ranges() => {
            return Outcome::Unknown(UnknownReason::SchemeMismatch, shape);
        }
        RangeKind::Semver | RangeKind::Ecosystem => {}
        _ => return Outcome::Unknown(UnknownReason::UnsupportedRangeType, shape),
    }
    if range.events.is_empty() {
        return Outcome::Unknown(UnknownReason::MalformedRange, shape);
    }

    // Read every event first; the worst problem (by reason, then position) is
    // reported, so the order of the events never changes the answer.
    let at = |event: usize| Place::Range {
        range: range_index,
        event: Some(event),
    };
    let mut problem: Option<(UnknownReason, Place)> = None;
    let mut flag = |reason: UnknownReason, place: Place| {
        if problem.is_none_or(|(r, _)| reason < r) {
            problem = Some((reason, place));
        }
    };
    let mut steps: Vec<(Coordinate<S::Version>, Step, usize)> = Vec::new();
    let mut limits: Vec<Coordinate<S::Version>> = Vec::new();
    let mut unbounded = false;
    for (index, event) in range.events.iter().enumerate() {
        match event {
            Event::Introduced(v) => match v.expose_untrusted().as_str() {
                "0" => steps.push((Coordinate::NegativeInfinity, Step::Introduced, index)),
                s => match scheme.parse(s) {
                    Ok(v) => steps.push((Coordinate::At(v), Step::Introduced, index)),
                    Err(_) => flag(UnknownReason::UnparseableBoundary, at(index)),
                },
            },
            Event::Fixed(v) | Event::LastAffected(v) => {
                let step = if matches!(event, Event::Fixed(_)) {
                    Step::Fixed
                } else {
                    Step::LastAffected
                };
                match v.expose_untrusted().as_str() {
                    "0" => flag(UnknownReason::MalformedRange, at(index)),
                    s => match scheme.parse(s) {
                        Ok(v) => steps.push((Coordinate::At(v), step, index)),
                        Err(_) => flag(UnknownReason::UnparseableBoundary, at(index)),
                    },
                }
            }
            Event::Limit(v) => match v.expose_untrusted().as_str() {
                "*" => unbounded = true,
                s => match scheme.parse(s) {
                    Ok(v) => limits.push(Coordinate::At(v)),
                    Err(_) => flag(UnknownReason::UnparseableLimit, at(index)),
                },
            },
            _ => flag(UnknownReason::UnknownEventKind, at(index)),
        }
    }
    let has = |kind: &dyn Fn(&Event) -> bool| range.events.iter().any(kind);
    if has(&|e| matches!(e, Event::Fixed(_))) && has(&|e| matches!(e, Event::LastAffected(_))) {
        flag(UnknownReason::MalformedRange, shape);
    }
    if !has(&|e| matches!(e, Event::Introduced(_))) {
        flag(UnknownReason::MalformedRange, shape);
    }

    // Sort by position, then kind, then written order; drop exact duplicates.
    steps.sort();
    steps.dedup_by(|b, a| a.0 == b.0 && a.1 == b.1);
    for pair in steps.windows(2) {
        if let [a, b] = pair
            && a.0 == b.0
        {
            flag(UnknownReason::ConflictingEvents, at(b.2));
        }
    }
    if let Some((reason, place)) = problem {
        return Outcome::Unknown(reason, place);
    }

    // The last transition at or before the candidate decides.
    let mut open = false;
    let mut decided_by = None;
    for (coordinate, step, index) in &steps {
        let reached = match (coordinate, step) {
            (Coordinate::NegativeInfinity, _) => true,
            (Coordinate::At(v), Step::LastAffected) => v < candidate,
            (Coordinate::At(v), _) => v <= candidate,
        };
        if !reached {
            break;
        }
        open = *step == Step::Introduced;
        decided_by = Some(*index);
    }
    if !open {
        return Outcome::Out;
    }
    let below_a_limit = unbounded
        || limits.is_empty()
        || limits
            .iter()
            .any(|l| matches!(l, Coordinate::At(v) if candidate < v));
    if below_a_limit {
        Outcome::In(Place::Range {
            range: range_index,
            event: decided_by,
        })
    } else {
        Outcome::Out
    }
}
