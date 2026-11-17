//! Evaluates one affected entry's ranges and listed versions for one installed
//! version (design 2.1, section 3).

use crate::osv::{Advisory, AffectedEntry, Event, GapKind, Range, RangeKind};
use crate::version::{Candidate, VersionScheme};

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
///
/// The declaration order is load-bearing: when several things are unknown at
/// once, the evaluator reports the smallest reason (first declared), so the
/// answer never depends on the order of events, ranges or list items. Earlier
/// means more fundamental.
#[derive(Clone, Copy, Debug, PartialEq, Eq, PartialOrd, Ord)]
#[non_exhaustive]
pub enum UnknownReason {
    /// The installed version is not known.
    InstalledVersionUnknown,
    /// The scheme cannot read the installed version.
    InstalledVersionUnparseable,
    /// The record as a whole is uncertain: the intake recorded that it was
    /// truncated or declared a schema version it does not read.
    RecordUncertain,
    /// A `SEMVER` range met a scheme that has not declared SemVer compatibility.
    SchemeMismatch,
    /// The scheme has no order (identity only), so ranges cannot be evaluated.
    SchemeDoesNotOrder,
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
    /// A range with a malformed shape: no events, no `introduced`, both `fixed`
    /// and `last_affected`, `"0"` on a non-`introduced` event, events that do
    /// not alternate opening and closing, an `introduced` or `last_affected` at or
    /// above every limit of its own range, or a `fixed` above every limit.
    ///
    /// "A closing with nothing open" is deliberately stricter than OSV, which
    /// ignores a redundant closing: here it is `MalformedRange`, because a
    /// record that contradicts itself is a coverage gap, not a clearance.
    MalformedRange,
    /// Two different event kinds at the same coordinate that do not form a
    /// single-release range.
    ConflictingEvents,
    /// A listed version the scheme cannot compare with the installed one.
    UnreadableListedVersion,
    /// A listed version equals the installed one by order but is spelled
    /// differently, so it is neither a hit nor a miss.
    SameVersionDifferentSpelling,
    /// The installed version is only known to lie in an interval that the
    /// ranges or the list do not settle.
    CandidateIsAnInterval,
    /// The entry has no usable range and no listed version.
    NoUsableRangeOrVersions,
    /// A channel product's two orders (its own and literal SemVer) disagree, or
    /// only one of them could answer. Declared last on purpose: order is
    /// load-bearing, and this is the least fundamental reason.
    SchemeConflict,
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
        UnknownReason::RecordUncertain => {
            "Guard Dog could not read this advisory completely, so it cannot rule this version out. Is the installed version affected according to the advisory's own source?"
        }
        UnknownReason::SchemeMismatch => {
            "This advisory's ranges assume SemVer, but this product uses another version scheme. Which upstream release is installed, and has a reviewed mapping been added for it?"
        }
        UnknownReason::SchemeDoesNotOrder => {
            "This product's versions cannot be put in order, so a range cannot be checked. Which upstream release is installed?"
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
        UnknownReason::SameVersionDifferentSpelling => {
            "The advisory lists a version that equals the installed one in order but is written differently. Is the installed build the listed release?"
        }
        UnknownReason::CandidateIsAnInterval => {
            "Only a span of possible versions is known for the installed build. Which exact upstream release is it?"
        }
        UnknownReason::NoUsableRangeOrVersions => {
            "This advisory lists no usable range or version for this package. Which versions does the advisory's source say are affected?"
        }
        UnknownReason::SchemeConflict => {
            "Is this product a release candidate? Updating to the final release settles it."
        }
    }
}

pub(crate) fn unknown(entry: usize, place: Place, reason: UnknownReason) -> VersionEvidence {
    VersionEvidence::Unknown {
        reason,
        question: question(reason).to_string(),
        at: Location { entry, place },
    }
}

/// Keeps the smallest reason (first seen on a tie).
fn keep_smallest(slot: &mut Option<(UnknownReason, Place)>, reason: UnknownReason, place: Place) {
    if slot.is_none_or(|(r, _)| reason < r) {
        *slot = Some((reason, place));
    }
}

/// Evaluates entry `entry_index` of `advisory` for `installed` with the
/// caller's `scheme`.
///
/// Ranges and the `versions` list are a union: any positive evidence wins, then
/// any unknown, and only when every range and the whole list exclude the
/// installed version is the answer [`VersionEvidence::OutOfRange`]. The scheme
/// is the caller's choice; the range type never selects a parser.
///
/// A record the intake marked as truncated (`GapsTruncated`) or as declaring an
/// unexpected schema version (`UnexpectedSchemaVersion`) can never produce
/// `OutOfRange`: that answer becomes `Unknown(RecordUncertain)`. Positive
/// evidence stands. Other gaps are about single fields, ranges or entries, and
/// the evaluator sees those directly in the entry.
///
/// This is a primitive: the caller must pass the scheme the catalog names for
/// the product. A product whose catalog scheme is `semver-beta` (LND, Lightning
/// Terminal) is never evaluated here with `SemVer` or `GoTag`; that gives one
/// order's answer alone. Use [`evaluate_channel_entry`](crate::evaluate_channel_entry)
/// (the bare `ChannelScheme` answers nothing here). A Bitcoin Core value read
/// from `getnetworkinfo.subversion` uses `BitcoinCore::new(RcEvidence::Unknown)`.
/// The product dispatch (2.1 PR 7) will be the one public entry point that
/// applies these rules.
pub fn evaluate_entry<S: VersionScheme + ?Sized>(
    scheme: &S,
    advisory: &Advisory,
    entry_index: usize,
    installed: Option<&str>,
) -> VersionEvidence {
    evaluate_entry_with(scheme, &|_| scheme, advisory, entry_index, installed)
}

/// Crate-private: like [`evaluate_entry`], but each range's events are read by
/// the scheme `range_scheme` picks for that range's kind. The installed value,
/// the listed versions and the interval question use `scheme`. Both share one
/// version type.
pub(crate) fn evaluate_entry_with<'a, S, R>(
    scheme: &S,
    range_scheme: &dyn Fn(&RangeKind) -> &'a R,
    advisory: &Advisory,
    entry_index: usize,
    installed: Option<&str>,
) -> VersionEvidence
where
    S: VersionScheme + ?Sized,
    R: VersionScheme<Version = S::Version> + ?Sized + 'a,
{
    let Some(entry) = advisory.affected.get(entry_index) else {
        return unknown(
            entry_index,
            Place::Entry,
            UnknownReason::NoUsableRangeOrVersions,
        );
    };
    if !scheme.answers_alone() {
        return unknown(entry_index, Place::Entry, UnknownReason::SchemeMismatch);
    }
    let mut result = evaluate_inner(scheme, range_scheme, entry_index, entry, installed);
    if let VersionEvidence::Unknown {
        reason: UnknownReason::CandidateIsAnInterval,
        question,
        ..
    } = &mut result
    {
        *question = scheme.interval_question().to_string();
    }
    let uncertain = advisory.gaps.iter().any(|g| {
        matches!(
            g.kind,
            GapKind::GapsTruncated | GapKind::UnexpectedSchemaVersion
        )
    });
    if uncertain && result == VersionEvidence::OutOfRange {
        return unknown(entry_index, Place::Entry, UnknownReason::RecordUncertain);
    }
    result
}

fn evaluate_inner<'a, S, R>(
    scheme: &S,
    range_scheme: &dyn Fn(&RangeKind) -> &'a R,
    entry_index: usize,
    entry: &AffectedEntry,
    installed: Option<&str>,
) -> VersionEvidence
where
    S: VersionScheme + ?Sized,
    R: VersionScheme<Version = S::Version> + ?Sized + 'a,
{
    let whole = Place::Entry;
    let Some(raw) = installed else {
        return unknown(entry_index, whole, UnknownReason::InstalledVersionUnknown);
    };
    let candidate = scheme.candidate(raw).ok();
    let mut first_unknown: Option<(UnknownReason, Place)> = None;
    if candidate.is_none() {
        keep_smallest(
            &mut first_unknown,
            UnknownReason::InstalledVersionUnparseable,
            whole,
        );
    }

    let mut positive: Option<Place> = None;
    for (index, range) in entry.ranges.iter().enumerate() {
        match eval_range(range_scheme(&range.kind), index, range, candidate.as_ref()) {
            Outcome::In(place) => {
                positive.get_or_insert(place);
            }
            Outcome::Out => {}
            Outcome::Unknown(reason, place) => keep_smallest(&mut first_unknown, reason, place),
        }
    }
    // A value the scheme refused as installed (for example an rcN from a source
    // that drops rcN, or a dirty Go build) is never matched against the list.
    let listed_items = if candidate.is_some() {
        entry.versions.as_slice()
    } else {
        &[]
    };
    for (index, item) in listed_items.iter().enumerate() {
        let listed = item.expose_untrusted().trim_ascii();
        let place = Place::Listed { index };
        match &candidate {
            Some(Candidate::Between { low, high }) => match scheme.parse(listed) {
                Ok(l) if l >= *low && high.as_ref().is_none_or(|h| l < *h) => {
                    keep_smallest(
                        &mut first_unknown,
                        UnknownReason::CandidateIsAnInterval,
                        place,
                    );
                }
                Ok(_) => {}
                Err(_) => keep_smallest(
                    &mut first_unknown,
                    UnknownReason::UnreadableListedVersion,
                    place,
                ),
            },
            other => match scheme.same_identity(raw, listed) {
                Some(true) => {
                    positive.get_or_insert(place);
                }
                Some(false) => {
                    if let Some(Candidate::Exact(v)) = other
                        && scheme.same_version(v, listed) == Some(true)
                    {
                        keep_smallest(
                            &mut first_unknown,
                            UnknownReason::SameVersionDifferentSpelling,
                            place,
                        );
                    }
                }
                None => keep_smallest(
                    &mut first_unknown,
                    UnknownReason::UnreadableListedVersion,
                    place,
                ),
            },
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

/// The answer for one range, before the union.
enum Outcome {
    In(Place),
    Out,
    Unknown(UnknownReason, Place),
}

/// A position on the version line: "0" starts before every version.
#[derive(Clone, PartialEq, Eq, PartialOrd, Ord)]
enum Coordinate<V> {
    NegativeInfinity,
    At(V),
}

/// Event kinds that move the state, in the order they sort at one coordinate.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
enum Kind {
    Introduced,
    Fixed,
    LastAffected,
}

struct Step<V> {
    coordinate: Coordinate<V>,
    kind: Kind,
    index: usize,
}

/// What happens at one coordinate once ties are settled.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Op {
    Open,
    Close(Kind),
    /// `introduced` and `last_affected` at one release, with nothing open below:
    /// exactly that release.
    Point,
}

struct Group<V> {
    coordinate: Coordinate<V>,
    op: Op,
    index: usize,
}

/// Whether the groups leave a range open at `candidate`, and which event decided.
fn state_at<V: Ord>(groups: &[Group<V>], candidate: &V) -> (bool, Option<usize>) {
    let mut open = false;
    let mut decided_by = None;
    for g in groups {
        let (reached, strictly_below) = match &g.coordinate {
            Coordinate::NegativeInfinity => (true, true),
            Coordinate::At(v) => (v <= candidate, v < candidate),
        };
        let reached = match g.op {
            Op::Close(Kind::LastAffected) => strictly_below,
            _ => reached,
        };
        if !reached {
            break;
        }
        open = match g.op {
            Op::Open => true,
            Op::Close(_) => false,
            Op::Point => !strictly_below,
        };
        decided_by = Some(g.index);
    }
    (open, decided_by)
}

fn eval_range<S: VersionScheme + ?Sized>(
    scheme: &S,
    range_index: usize,
    range: &Range,
    candidate: Option<&Candidate<S::Version>>,
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
        RangeKind::Ecosystem if !scheme.reads_ecosystem_ranges() => {
            return Outcome::Unknown(UnknownReason::SchemeMismatch, shape);
        }
        RangeKind::Semver | RangeKind::Ecosystem => {}
        _ => return Outcome::Unknown(UnknownReason::UnsupportedRangeType, shape),
    }
    if !scheme.orders() {
        return Outcome::Unknown(UnknownReason::SchemeDoesNotOrder, shape);
    }
    if range.events.is_empty() {
        return Outcome::Unknown(UnknownReason::MalformedRange, shape);
    }

    // Read every event first; the smallest problem is reported, so the order of
    // the events never changes the answer.
    let at = |event: usize| Place::Range {
        range: range_index,
        event: Some(event),
    };
    let mut problem: Option<(UnknownReason, Place)> = None;
    let mut steps: Vec<Step<S::Version>> = Vec::new();
    let mut limits: Vec<S::Version> = Vec::new();
    let mut unbounded = false;
    for (index, event) in range.events.iter().enumerate() {
        match event {
            Event::Introduced(v) => match v.expose_untrusted().trim_ascii() {
                "0" => steps.push(Step {
                    coordinate: Coordinate::NegativeInfinity,
                    kind: Kind::Introduced,
                    index,
                }),
                s => match scheme.parse(s) {
                    Ok(v) => steps.push(Step {
                        coordinate: Coordinate::At(v),
                        kind: Kind::Introduced,
                        index,
                    }),
                    Err(_) => {
                        keep_smallest(&mut problem, UnknownReason::UnparseableBoundary, at(index))
                    }
                },
            },
            Event::Fixed(v) | Event::LastAffected(v) => {
                let kind = if matches!(event, Event::Fixed(_)) {
                    Kind::Fixed
                } else {
                    Kind::LastAffected
                };
                match v.expose_untrusted().trim_ascii() {
                    "0" => keep_smallest(&mut problem, UnknownReason::MalformedRange, at(index)),
                    s => match scheme.parse(s) {
                        Ok(v) => steps.push(Step {
                            coordinate: Coordinate::At(v),
                            kind,
                            index,
                        }),
                        Err(_) => keep_smallest(
                            &mut problem,
                            UnknownReason::UnparseableBoundary,
                            at(index),
                        ),
                    },
                }
            }
            Event::Limit(v) => match v.expose_untrusted().trim_ascii() {
                "*" => unbounded = true,
                "0" => keep_smallest(&mut problem, UnknownReason::MalformedRange, at(index)),
                s => match scheme.parse(s) {
                    Ok(v) => limits.push(v),
                    Err(_) => {
                        keep_smallest(&mut problem, UnknownReason::UnparseableLimit, at(index));
                    }
                },
            },
            _ => keep_smallest(&mut problem, UnknownReason::UnknownEventKind, at(index)),
        }
    }
    let has = |f: &dyn Fn(&Event) -> bool| range.events.iter().any(f);
    if has(&|e| matches!(e, Event::Fixed(_))) && has(&|e| matches!(e, Event::LastAffected(_))) {
        keep_smallest(&mut problem, UnknownReason::MalformedRange, shape);
    }
    if !has(&|e| matches!(e, Event::Introduced(_))) {
        keep_smallest(&mut problem, UnknownReason::MalformedRange, shape);
    }

    // Sort by position, then kind, then written order; drop exact duplicates.
    steps.sort_by(|a, b| (&a.coordinate, a.kind, a.index).cmp(&(&b.coordinate, b.kind, b.index)));
    steps.dedup_by(|b, a| a.coordinate == b.coordinate && a.kind == b.kind);

    // Settle ties and check that openings and closings alternate.
    let mut groups: Vec<Group<S::Version>> = Vec::new();
    let mut open = false;
    let mut i = 0;
    while let Some(first) = steps.get(i) {
        let mut j = i + 1;
        while steps
            .get(j)
            .is_some_and(|s| s.coordinate == first.coordinate)
        {
            j += 1;
        }
        let run = steps.get(i..j).unwrap_or_default();
        let op = match run {
            [only] => match only.kind {
                Kind::Introduced => Op::Open,
                k => Op::Close(k),
            },
            [a, b] if a.kind == Kind::Introduced && b.kind == Kind::LastAffected && !open => {
                Op::Point
            }
            _ => {
                keep_smallest(
                    &mut problem,
                    UnknownReason::ConflictingEvents,
                    at(first.index),
                );
                Op::Open
            }
        };
        match op {
            Op::Open => open = true,
            Op::Close(_) => {
                if !open {
                    keep_smallest(&mut problem, UnknownReason::MalformedRange, at(first.index));
                }
                open = false;
            }
            Op::Point => open = false,
        }
        groups.push(Group {
            coordinate: first.coordinate.clone(),
            op,
            index: first.index,
        });
        i = j;
    }

    // A range cannot reopen at or beyond every one of its own limits. Limits
    // expand scope, so a limit above the reopening (or `*`) keeps it reachable.
    for g in &groups {
        if let (Coordinate::At(c), Op::Open | Op::Point) = (&g.coordinate, g.op)
            && !unbounded
            && !limits.is_empty()
            && !limits.iter().any(|l| l > c)
        {
            keep_smallest(&mut problem, UnknownReason::MalformedRange, at(g.index));
        }
    }
    // The same for closings: with ordinary limits only, a `last_affected` at or
    // above every limit, or a `fixed` strictly above every limit, contradicts
    // the range's own cap.
    if !unbounded && !limits.is_empty() {
        for g in &groups {
            if let (Coordinate::At(c), Op::Close(kind)) = (&g.coordinate, g.op) {
                let contradicts = match kind {
                    Kind::LastAffected => !limits.iter().any(|l| l > c),
                    _ => !limits.iter().any(|l| l >= c),
                };
                if contradicts {
                    keep_smallest(&mut problem, UnknownReason::MalformedRange, at(g.index));
                }
            }
        }
    }
    if let Some((reason, place)) = problem {
        return Outcome::Unknown(reason, place);
    }

    let Some(candidate) = candidate else {
        return Outcome::Unknown(UnknownReason::InstalledVersionUnparseable, shape);
    };
    match candidate {
        Candidate::Exact(v) => {
            let (open, decided_by) = state_at(&groups, v);
            let below_a_limit = unbounded || limits.is_empty() || limits.iter().any(|l| v < l);
            if open && below_a_limit {
                Outcome::In(Place::Range {
                    range: range_index,
                    event: decided_by,
                })
            } else {
                Outcome::Out
            }
        }
        Candidate::Between { low, high } => {
            let (open_low, _) = state_at(&groups, low);
            let opens_inside = groups.iter().any(|g| {
                matches!(g.op, Op::Open | Op::Point)
                    && matches!(&g.coordinate, Coordinate::At(c)
                        if c > low && high.as_ref().is_none_or(|h| c <= h))
            });
            // Every version in [low, high) is in range when the range is open at
            // low, nothing closes it from low up to high, and high is within a
            // limit (or there is none).
            let closes_inside = groups.iter().any(|g| {
                matches!(g.op, Op::Close(_) | Op::Point)
                    && matches!(&g.coordinate, Coordinate::At(c)
                        if c >= low && high.as_ref().is_none_or(|h| c < h))
            });
            let within_a_limit = unbounded
                || limits.is_empty()
                || high.as_ref().is_some_and(|h| limits.iter().any(|l| h <= l));
            if open_low && !closes_inside && within_a_limit {
                let (_, decided_by) = state_at(&groups, low);
                Outcome::In(Place::Range {
                    range: range_index,
                    event: decided_by,
                })
            } else if open_low || opens_inside {
                Outcome::Unknown(UnknownReason::CandidateIsAnInterval, shape)
            } else {
                Outcome::Out
            }
        }
    }
}
