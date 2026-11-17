//! The contract a version scheme gives the range evaluator.
//!
//! The catalog picks the scheme for a product; an OSV range type never picks a
//! parser (design 2.1, "scheme authority"). The schemes themselves (SemVer,
//! Bitcoin Core, PEP 440, ...) arrive in later pull requests and implement
//! [`VersionScheme`]. The evaluator in [`crate::range`] only needs what is here.

use std::fmt;

/// Why a scheme could not read a version string.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[non_exhaustive]
pub enum VersionError {
    /// The string is not a version of this scheme.
    Malformed,
    /// The string is longer than the scheme accepts.
    TooLong,
}

impl fmt::Display for VersionError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        f.write_str(match self {
            Self::Malformed => "not a version of this scheme",
            Self::TooLong => "version is too long",
        })
    }
}

impl std::error::Error for VersionError {}

/// What is known about where the installed version sits on the scheme's line.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Candidate<V> {
    /// Exactly this version.
    Exact(V),
    /// Somewhere from `low` (inclusive) up to `high` (exclusive; `None` means
    /// no upper end). Git-describe's "at or after tag T" and Core's release
    /// candidate that reads as a final release are of this shape. It is out of
    /// range only if no range step opens inside the interval and `low` itself is
    /// out; otherwise the evaluator says it cannot tell.
    Between {
        /// The lowest version it can be.
        low: V,
        /// The first version it cannot be; `None` is unbounded.
        high: Option<V>,
    },
}

/// One ordered version scheme.
///
/// Rules every implementation must keep:
/// - `parse` consumes the whole string and never guesses; anything it cannot
///   read is an error, never a partial or lexical fallback.
/// - `Version`'s `Ord` is the scheme's precedence order, and `Eq` agrees with it.
///   Precedence equality is not identity: build metadata or a local label can
///   differ between two versions that compare equal.
/// - `same_identity` compares exact identity after only the scheme's documented
///   normalization. `None` means the scheme cannot say (a string it cannot read).
/// - `candidate` reads the installed value (advisory boundaries always go
///   through `parse`). The default is an exact version; a scheme that can only
///   place the installed value in an interval returns `Between`.
/// - A scheme that has no order at all (opaque, equality only) returns `false`
///   from `orders`: every ordered range is then unknown, and only the listed
///   versions are checked, by identity.
/// - Channel schemes with two orders (such as lnd's SemVer-and-beta check) are
///   evaluated by the caller running the evaluator once per scheme; one scheme
///   object never mixes two orders. The combination rule: in range only if both
///   say in range, out of range only if both say out of range, otherwise
///   `Unknown(SchemeConflict)` (a reason the channel-scheme PR adds).
pub trait VersionScheme {
    /// A parsed version, ordered by precedence.
    type Version: Ord + Clone;

    /// Reads one version string.
    fn parse(&self, raw: &str) -> Result<Self::Version, VersionError>;

    /// Reads the installed version.
    fn candidate(&self, raw: &str) -> Result<Candidate<Self::Version>, VersionError> {
        self.parse(raw).map(Candidate::Exact)
    }

    /// Whether two raw strings name the same exact version, or `None` if either
    /// cannot be read.
    fn same_identity(&self, a: &str, b: &str) -> Option<bool>;

    /// Whether `listed` is precedence-equal to `installed`, or `None` if it
    /// cannot be read. A listed version that is precedence-equal but not the
    /// same identity is never treated as a miss.
    fn same_version(&self, installed: &Self::Version, listed: &str) -> Option<bool> {
        self.parse(listed).ok().map(|l| l == *installed)
    }

    /// Whether this scheme has declared that it can evaluate `SEMVER` ranges.
    /// A scheme that has not declared it makes a `SEMVER` range `Unknown`,
    /// never a SemVer fallback.
    fn reads_semver_ranges(&self) -> bool;

    /// Whether versions of this scheme have an order at all.
    fn orders(&self) -> bool;
}
